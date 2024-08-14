 # Testing AWS Security Hub Findings Collection

This is a simple script to test AWS Security Hub findings collection.
It will create the context for breaking a config rule, which is going to generate a finding in Security Hub. It will read the finding and fix the issue, which will resolve the finding. After that, it will check for the finding in Security Hub again and make sure it is resolved.

It interacts with AWS Security Hub, AWS Config and AWS Accounts. It will use the boundary parameter to search for existing connections.

## Environment variables:
* `FINDINGTEST_ORG_ID` - (UUID) - your organization ID
* `FINDINGTEST_API_KEY` - (UUID) - your API key
* `FINDINGTEST_BOUNDARY_ID` - (UUID) - your boundary ID
* `FINDINGTEST_AWS_ACCOUNT_ID` - your AWS account ID to test against
* `FINDINGTEST_SERVER_URL` - (URL) optional - ZeroBias URL - default `https://api.app.zerobias.com`
* `FINDINGTEST_TIMEOUT_MINUTES` - (Number) optional - The number of minutes wait for a config rule evaluation to complete - default 10 minutes.

*Note:* the project uses the `dotenv` package to load the environment variables from the `.env` file. You can create a `.env` file in the root of the project and set the environment variables there.  
.env file structure:
```bash
FINDINGTEST_SERVER_URL=https://api.app.zerobias.com
FINDINGTEST_ORG_ID=00000000-0000-0000-0000-000000000000
FINDINGTEST_API_KEY=00000000-0000-0000-0000-000000000000
FINDINGTEST_BOUNDARY_ID=00000000-0000-0000-0000-000000000000
FINDINGTEST_AWS_ACCOUNT_ID=123123123132
FINDINGTEST_TIMEOUT_MINUTES=5
```

## Permissions needed:
:warning:  
The following `write` premissions needed on the connections:
- account:DeleteAlternateContact
- account:PutAlternateContact
- config:StartConfigRulesEvaluation

## Steps:
1. Validate the connection to zeroBias
1. Validate the boundary id
1. Find the AWS connections in the boundary
1. Store the security alternate contact information
1. Delete the alternate contact information *
1. Find the config rule name for the rule that requires a security alternate contact *
1. Start the config rule evaluation *
1. Wait for the config rule evaluation to complete *
1. Read and store the latest updated AWS Security Hub finding for that rule *
1. Put the alternate contact information back *
1. Start the config rule evaluation again
1. Wait for the config rule evaluation to complete
1. Read and store the latest updated AWS Security Hub finding for that rule again
1. Compare the two findings to make sure the finding is resolved

\* - if the alternate config exists

## Usage
1. Set the environment variables
1. Install the dependencies: `npm ci`
1. Build the project: `npm run build`
1. Run the test script: `npm run test`

### Important Note:  
The initial value of the security alternate contact will be saved to `.deleted_alternate_contact_{timestamp}.json` file.  
When the value is restored, the file will be deleted. In case of an error that results in the loss of the alternate contact value, you can restore the value manually by using the following aws CLI command:
```bash
aws account put-alternate-contact --alternate-contact-type SECURITY --email-address "$EMAIL" --name "$NAME" --phone "$PHONENO" --title "$TITLE"
```
