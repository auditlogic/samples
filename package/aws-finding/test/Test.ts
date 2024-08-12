import { Compliance } from '@auditlogic/module-amazon-aws-securityhub';
import { URL, UUID } from '@auditmation/types-core-js';
import { expect } from 'chai';
import { config } from 'dotenv';
import { AwsFindingTester } from '../src';
import { latestUpdatedFinding } from '../src/Util';

config();

describe('AWS Finding test', () => {
  it('should run', async () => {
    const orgId = process.env.FINDINGTEST_ORG_ID;
    const apiKey = process.env.FINDINGTEST_API_KEY;
    const boundaryId = process.env.FINDINGTEST_BOUNDARY_ID;
    const accountId = process.env.FINDINGTEST_AWS_ACCOUNT_ID;
    const serverUrl = process.env.FINDINGTEST_SERVER_URL;
    const evalMinutes = process.env.FINDINGTEST_EVAL_MINUTES;

    if (!orgId || !apiKey || !boundaryId || !accountId) {
      throw new Error('Missing environment variables for test');
    }

    const tester = new AwsFindingTester(
      new UUID(orgId),
      apiKey,
      new UUID(boundaryId),
      accountId,
      serverUrl ? new URL(serverUrl) : undefined,
      evalMinutes ? parseInt(evalMinutes) : undefined
    );

    const { initialFindings, finalFindings } = await tester.run();

    const latestInitial = latestUpdatedFinding(initialFindings);
    const latestFinal = latestUpdatedFinding(finalFindings);

    expect(latestInitial).to.not.deep.equal(latestFinal);

    expect(latestInitial?.compliance?.status).to.equal(Compliance.StatusEnum.Failed);
    expect(latestFinal?.compliance?.status).to.equal(Compliance.StatusEnum.Passed);

  }).timeout(0);
})
