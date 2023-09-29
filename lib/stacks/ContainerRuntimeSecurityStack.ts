import { Duration, Stack, StackProps, RemovalPolicy } from "aws-cdk-lib";
import { Construct } from "constructs";
import {
  AwsCustomResource,
  AwsCustomResourcePolicy,
} from "aws-cdk-lib/custom-resources";
import { PolicyStatement } from "aws-cdk-lib/aws-iam";
import {
  EventbridgeToLambda,
  EventbridgeToLambdaProps,
} from "@aws-solutions-constructs/aws-eventbridge-lambda";
import path = require("path");
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as iam from "aws-cdk-lib/aws-iam";
import * as events from "aws-cdk-lib/aws-events";
import { LambdaFunctionProps } from "aws-cdk-lib/aws-events-targets";
import * as logs from "aws-cdk-lib/aws-logs";

export class ContainerRuntimeSecurityStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    this.configureEnhancedScanning();
    this.createEventBridgeToLambda();
  }

  configureEnhancedScanning() {
    
      new AwsCustomResource(this, "ecrEnhancedScanning", {
        onCreate: {
          service: "ECR",
          action: "putRegistryScanningConfiguration",
          physicalResourceId: { id: "putRegistryScanningConfiguration" },
          parameters: {
            rules: [
              {
                repositoryFilters: ["*"],
                scanFrequency: "SCAN_ON_PUSH",
              },
            ],
            scanType: "ENHANCED",
          },
        },
        onUpdate: {
          service: "ECR",
          action: "putRegistryScanningConfiguration",
          physicalResourceId: { id: "putRegistryScanningConfiguration" },
          parameters: {
            scanType: "ENHANCED",
          },
        },
        
        policy: AwsCustomResourcePolicy.fromStatements([
          new PolicyStatement({
            actions: [
              "iam:CreateServiceLinkedRole",
              "inspector2:Enable",
              "ecr:PutRegistryScanningConfiguration",
            ],
            resources: AwsCustomResourcePolicy.ANY_RESOURCE,
          }),
        ]),
      }),



      new AwsCustomResource(this, "inspectorEcrConfiguration", {
        // installLatestAwsSdk: true, //<- must be turned on for first deployment, after that can be commented out
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
        
        policy: AwsCustomResourcePolicy.fromStatements([
          new PolicyStatement({
            actions: [
              "iam:CreateServiceLinkedRole",
              // "inspector2:listMembers",
              "inspector2:UpdateConfiguration",
            ],
            resources: AwsCustomResourcePolicy.ANY_RESOURCE,
          }),
        ]),
      })
  }

  createEventBridgeToLambda() {

    const constructProps: EventbridgeToLambdaProps = {
      lambdaFunctionProps: {
        code: lambda.Code.fromAsset(
          path.join(__dirname, "../", "lambdas", "CheckEcs"),
          { exclude: ["*.ts", "*.d.ts"] }
        ),
        description: "Check ECS for found vulnerabilty in running images",
        functionName: "CheckECS-Lambda",
        runtime: lambda.Runtime.NODEJS_18_X,
        handler: "index.handler",
        // role: lambdaRole,
        reservedConcurrentExecutions: 1,
        initialPolicy: [
          new iam.PolicyStatement({
            resources: ["*"],
            actions: ["ecs:ListClusters", "ecs:ListTasks", "ecs:DescribeTasks", "ecs:DescribeClusters"],
          }),
        ],
        logRetention: logs.RetentionDays.ONE_MONTH,
      },

      eventRuleProps: {
        ruleName: "ecr-enhanced-scanning-vulnerability-found",
        eventPattern: {
          source: ["aws.inspector2"],
          detailType: ["Inspector2 Finding"],
          resources:  events.Match.prefix("arn:aws:ecr") 
        },
        enabled: true,
      },
    };

    const ebl = new EventbridgeToLambda(
      this,
      "vulnerable-ecr-image-found-lambda",
      constructProps
    );
  }
}
