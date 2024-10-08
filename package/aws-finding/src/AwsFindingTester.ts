import { AccountsHubImpl, AlternateContact, ContactTypeEnum } from '@auditlogic/module-amazon-aws-accounts';
import { ConfigHubImpl } from '@auditlogic/module-amazon-aws-config';
import { Finding, SecurityHubHubImpl } from '@auditlogic/module-amazon-aws-securityhub';
import { ConnectionMetadata } from '@auditmation/hub-core';
import { newHub } from '@auditmation/module-auditmation-auditmation-hub';
import { newPlatform } from '@auditmation/module-auditmation-auditmation-platform';
import { URL, UUID } from '@auditmation/types-core-js';
import { PromisePool } from '@supercharge/promise-pool';
import { rmSync, writeFileSync } from 'fs';
import { extractFindingConfigRule, latestUpdatedFinding, sleep } from './Util';

const CONFIG_PACKAGE_NAME = 'amazon.aws.config';
const SECURITY_HUB_PACKAGE_NAME = 'amazon.aws.securityhub';
const ACCOUNTS_PACKAGE_NAME = 'amazon.aws.accounts';

const GENERATOR_ID = 'security-control/Account.1';

const BACKUP_CONTACT_FILENAME = `.deleted_alternate_contact_${new Date().toISOString()}.json`;

export class AwsFindingTester {
  constructor(
    private orgId: UUID,
    private apiKey: string,
    private boundaryId: UUID,
    private awsAccountId: string,
    private serverUrl: URL = new URL('https://api.app.zerobias.com'),
    private evalMinutes: number = 3
  ) { }

  private get hubUrl(): URL {
    return new URL(`${this.serverUrl}hub`);
  }

  private platform = newPlatform();
  private hub = newHub();

  private config: ConfigHubImpl = new ConfigHubImpl();
  private securityHub: SecurityHubHubImpl = new SecurityHubHubImpl();
  private accounts: AccountsHubImpl = new AccountsHubImpl();

  private clients = {
    [CONFIG_PACKAGE_NAME]: this.config,
    [ACCOUNTS_PACKAGE_NAME]: this.accounts,
    [SECURITY_HUB_PACKAGE_NAME]: this.securityHub
  }

  private alternateContact?: AlternateContact;
  private ruleName?: string;

  public async run(): Promise<{ initialFindings: Finding[], finalFindings: Finding[] }> {

    await this.init();
    await this.makeConnections();

    this.alternateContact = await this.getCurrentSecurityContact();
    console.log(`Initial alternate contact stored: ${JSON.stringify(this.alternateContact)}`);
    writeFileSync(BACKUP_CONTACT_FILENAME, JSON.stringify(this.alternateContact, null, 2));

    await this.deleteAlternateContact();
    console.log('Alternate contact has been deleted.');

    this.ruleName = await this.getAccount1ConfigRuleName();
    console.log(`Config rule name: ${this.ruleName}`);

    await this.evalConfigRule(this.ruleName!);
    console.log(`Stared evaluation of config rule "${this.ruleName}"`);

    console.log(`Waiting for ${this.evalMinutes} minutes...`);
    await sleep(this.evalMinutes * 60);

    const initialFindings = await this.listAccount1Finding();
    console.log(`Gathered initial findings`);
    console.log(`Latest initial finding: ${JSON.stringify(latestUpdatedFinding(initialFindings), null, 2)}`);

    await this.updateSecurityContact(this.alternateContact);
    console.log('Alternate contact has been updated.');
    rmSync(BACKUP_CONTACT_FILENAME);

    await this.evalConfigRule(this.ruleName!);
    console.log(`Stared evaluation of config rule "${this.ruleName}"`);

    console.log(`Waiting for ${this.evalMinutes} minutes...`);
    await sleep(this.evalMinutes * 60);

    const finalFindings = await this.listAccount1Finding();
    console.log(`Gathered final findings`);
    console.log(`Latest final finding: ${JSON.stringify(latestUpdatedFinding(finalFindings), null, 2)}`);

    return { initialFindings, finalFindings };
  }

  private async init() {
    console.log(`\nConnecting to ${this.serverUrl}...\nOrg: ${this.orgId}`);
    console.log(`Eval minutes: ${this.evalMinutes}`);
    const connectionProfile = {
      orgId: this.orgId,
      apiKey: this.apiKey,
      url: this.serverUrl
    }
    await this.platform.connect(connectionProfile)
    await this.hub.connect(connectionProfile);

    await this.confirmBoundaryId();
  }

  private async confirmBoundaryId() {
    const boundary = await this.platform.getBoundaryApi().getBoundary(this.boundaryId);
    console.log(`Boundary "${boundary.name}" found.`);
  }

  private async makeConnections() {
    await this.makeConnection(CONFIG_PACKAGE_NAME);
    await this.makeConnection(SECURITY_HUB_PACKAGE_NAME);
    await this.makeConnection(ACCOUNTS_PACKAGE_NAME);
  }

  private async makeConnection(packageName: string) {
    const configConnectionId = await this.findConnectionId(packageName);

    try {
      await this.clients[packageName].connect({
        server: this.hubUrl,
        orgId: this.orgId,
        apiKey: this.apiKey,
        targetId: configConnectionId,
      })
      console.log(`Connected to ${packageName} successfully.`);
    } catch (e) {
      console.log(e)
      throw e;
    }
  }

  private async findConnectionId(packageName: string): Promise<UUID> {
    const boundaryProducts = await this.platform.getBoundaryApi().listBoundaryProductsByBoundary(this.boundaryId, 1, 500);

    console.log(`Looking for "${packageName}" connection for account "${this.awsAccountId}" in boundary...`)
    const boundaryProduct = boundaryProducts.items.find(product => product.productPackage === packageName);

    if (!boundaryProduct) {
      throw new Error(`No ${packageName} product found in boundary`);
    }
    console.log(`${packageName} boundary product: ${boundaryProduct.id}`);

    const connections = await this.platform.getBoundaryApi().listBoundaryProductConnections(this.boundaryId, boundaryProduct.id);

    const { results: connectionInfos } =
      await PromisePool.for(connections.items)
        .withConcurrency(2)
        .process(async (connection) => {
          return {
            connectionId: connection.connectionId,
            metadata: await this.getAwsConnectionMetadata(connection.connectionId)
          };
        });

    let connectionId = connectionInfos
      .find(
        info => info.metadata?.remoteSystemInfo?.account === this.awsAccountId
      )?.connectionId;

    if (!connectionId) {
      throw new Error(`No ${packageName} connection with status "ON" found for account ${this.awsAccountId}`);
    }

    console.log(`${packageName} Connection ID: ${connectionId}`);

    return connectionId;
  }

  private async getAwsConnectionMetadata(connectionId: UUID): Promise<ConnectionMetadata | undefined> {
    try {
      const metadata = await this.hub.getTargetApi().getTargetMetadata(connectionId);
      return metadata;
    }
    catch (e) {
      console.error(`${e?.['message']}`.substring(0, 100) + "...");
    }
    return undefined;
  }

  private async getCurrentSecurityContact() {
    return this.accounts.getAlternateContactApi().get(ContactTypeEnum.Security).catch(e => {
      console.log(`Error while trying to get alternate contact: ${e}`);
      throw e;
    });
  }

  private async deleteAlternateContact() {
    return this.accounts.getAlternateContactApi().delete(ContactTypeEnum.Security).catch(e => {
      console.log(`Error while trying to delete alternate contact: ${e}`);
      throw e;
    });
  }

  private async getAccount1ConfigRuleName() {
    const [finding] = await this.listAccount1Finding();
    return extractFindingConfigRule(finding);
  }

  private async listAccount1Finding() {
    try {
      const findings = await this.securityHub.getFindingApi().list(100, undefined, GENERATOR_ID);
      return findings.items;
    } catch (e) {
      console.log(`Error while trying to get Account.1 findings: ${e}`);
      throw e;
    }
  }

  private async updateSecurityContact(alternateContact: AlternateContact) {
    return this.accounts.getAlternateContactApi().update(
      {
        alternateContactType: ContactTypeEnum.Security,
        email: alternateContact.email!,
        name: alternateContact.name!,
        phone: alternateContact.phone!,
        title: alternateContact.title!
      }
    ).catch(e => {
      console.log(`Error while trying to update alternate contact: ${e}`);
      throw e;
    });
  }

  private async evalConfigRule(ruleName: string) {
    return this.config.getConfigRuleApi().start([
      ruleName
    ]).catch(e => {
      console.log(`Error while trying to start config rule evaluation: ${e}`);
      console.log(`Moving on...`);
    });
  }
}
