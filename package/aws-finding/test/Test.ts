import { Compliance } from '@auditlogic/module-amazon-aws-securityhub';
import { URL, UUID } from '@auditmation/types-core-js';
import { expect } from 'chai';
import { config } from 'dotenv';
import { AwsFindingTester } from '../src';

config();

describe('AWS Finding test', () => {
  it('should run', async () => {
    const orgId = process.env.FINDINGTEST_ORG_ID;
    const apiKey = process.env.FINDINGTEST_API_KEY;
    const boundaryId = process.env.FINDINGTEST_BOUNDARY_ID;
    const accountId = process.env.FINDINGTEST_AWS_ACCOUNT_ID;
    const serverUrl = process.env.FINDINGTEST_SERVER_URL;
    const timeoutMinutes = process.env.FINDINGTEST_TIMEOUT_MINUTES;

    if (!orgId || !apiKey || !boundaryId || !accountId) {
      throw new Error('Missing environment variables for test');
    }

    const tester = new AwsFindingTester(
      new UUID(orgId),
      apiKey,
      new UUID(boundaryId),
      accountId,
      serverUrl ? new URL(serverUrl) : undefined,
      timeoutMinutes ? parseInt(timeoutMinutes) : undefined
    );

    const { initialFinding, finalFinding } = await tester.run();


    // case 1: alternate contact existed
    if (initialFinding) {
      expect(initialFinding).to.not.deep.equal(finalFinding);

      expect(initialFinding?.compliance?.status).to.equal(Compliance.StatusEnum.Failed);
      expect(finalFinding?.compliance?.status).to.equal(Compliance.StatusEnum.Passed);
    }

    // case 2: alternate contact did not exist
    else {
      expect(finalFinding?.compliance?.status).to.equal(Compliance.StatusEnum.Failed); 
    }
  }).timeout(0);
})
