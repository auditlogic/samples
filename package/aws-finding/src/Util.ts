import { Finding } from '@auditlogic/module-amazon-aws-securityhub';

export const extractFindingConfigRule = (finding: Finding): string | undefined => {
  const productFields = Object.entries(finding?.productFields || {});
  const typeKey = productFields.find(([key, value]) => (
    key.startsWith('RelatedAWSResources:')
    && key.endsWith('/type')
    && value === 'AWS::Config::ConfigRule'))?.[0];
  const configRuleKey = typeKey ? typeKey.replace('/type', '/name') : undefined;
  const configRule = configRuleKey ? productFields.find(([key, _value]) => key === configRuleKey)?.[1] : undefined;

  return configRule;
};

export const sleep = (s: number) => new Promise((resolve) => setTimeout(resolve, s * 1000));

export const latestUpdatedFinding = (findings: Finding[]): Finding | undefined => {
  return findings
    .filter((f) => !!f.updated)
    .sort((a, b) => {
      return new Date(b.updated!).getTime() - new Date(a.updated!).getTime();
    })[0];
}
