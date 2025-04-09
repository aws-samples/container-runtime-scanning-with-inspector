import { Stack, StackProps } from "aws-cdk-lib";
import { Construct } from "constructs";
import {
  AwsCustomResource,
  AwsCustomResourcePolicy,
} from "aws-cdk-lib/custom-resources";
import {
  EventbridgeToLambda,
} from "@aws-solutions-constructs/aws-eventbridge-lambda";
import { join } from "path";
import { PolicyStatement } from "aws-cdk-lib/aws-iam";
import { Match } from "aws-cdk-lib/aws-events";
import { NodejsFunction } from "aws-cdk-lib/aws-lambda-nodejs";
import { Runtime } from "aws-cdk-lib/aws-lambda";
import { RetentionDays } from "aws-cdk-lib/aws-logs";

export class ContainerRuntimeSecurityStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);
    this.configureEnhancedScanning();
    this.createEventBridgeToLambda();
  }

  configureEnhancedScanning() {

    const enableInspector = new AwsCustomResource(this, "enableInspector", {
      installLatestAwsSdk: true,
      onUpdate: {
        service: "Inspector2",
        action: "enable",
        physicalResourceId: { id: "enableInspector" },
        parameters: {
          resourceTypes: ["ECR"],
        },
      },
      onDelete: {
        service: "Inspector2",
        action: "disable",
        physicalResourceId: { id: "disableInspector" },
        parameters: {
          resourceTypes: ["ECR"],
        },
      },
      policy: AwsCustomResourcePolicy.fromStatements([
        new PolicyStatement({
          actions: [
            "iam:CreateServiceLinkedRole",
            "inspector2:Enable",
            "inspector2:Disable",
          ],
          resources: AwsCustomResourcePolicy.ANY_RESOURCE,
        })
      ])
    })

    new AwsCustomResource(this, "inspectorEcrConfiguration", {
      installLatestAwsSdk: true,
      onUpdate: {
        service: "Inspector2",
        action: "updateConfiguration",
        physicalResourceId: { id: "updateConfiguration" },
        parameters: {
          ecrConfiguration: {
            rescanDuration: "DAYS_30",
          },
        },
      },
      policy: AwsCustomResourcePolicy.fromSdkCalls({
        resources: AwsCustomResourcePolicy.ANY_RESOURCE,
      }),
    }).node.addDependency(enableInspector)

    new AwsCustomResource(this, "ecrEnhancedScanning", {
      onUpdate: {
        service: "ECR",
        action: "putRegistryScanningConfiguration",
        physicalResourceId: { id: "putRegistryScanningConfiguration" },
        parameters: {
          scanType: "ENHANCED",
        },
      },
      policy: AwsCustomResourcePolicy.fromSdkCalls({
        resources: AwsCustomResourcePolicy.ANY_RESOURCE,
      }),
    }).node.addDependency(enableInspector)

  }

  createEventBridgeToLambda() {

    new EventbridgeToLambda(
      this,
      "vulnerable-ecr-image-found-lambda",
      {
        existingLambdaObj: new NodejsFunction(this, "CheckEcs", {
          entry: join(__dirname, "..", "lambdas", "CheckEcs", "index.ts"),
          handler: "index.handler",
          description: "Check ECS for found vulnerability in running images",
          functionName: "CheckECS-Lambda",
          reservedConcurrentExecutions: 1,
          initialPolicy: [
            new PolicyStatement({
              resources: ["*"],
              actions: ["ecs:ListClusters", "ecs:ListTasks", "ecs:DescribeTasks", "ecs:DescribeClusters"],
            }),
          ],
          logRetention: RetentionDays.ONE_MONTH,
          runtime: Runtime.NODEJS_LATEST,
        }),

        eventRuleProps: {
          ruleName: "ecr-enhanced-scanning-vulnerability-found",
          eventPattern: {
            source: ["aws.inspector2"],
            detailType: ["Inspector2 Finding"],
            resources: Match.prefix("arn:aws:ecr")
          },
          enabled: true,
        },
      }
    )
  }
}
