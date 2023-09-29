"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ContainerRuntimeSecurityStack = void 0;
const aws_cdk_lib_1 = require("aws-cdk-lib");
const custom_resources_1 = require("aws-cdk-lib/custom-resources");
const aws_iam_1 = require("aws-cdk-lib/aws-iam");
const aws_eventbridge_lambda_1 = require("@aws-solutions-constructs/aws-eventbridge-lambda");
const path = require("path");
const lambda = require("aws-cdk-lib/aws-lambda");
const iam = require("aws-cdk-lib/aws-iam");
const events = require("aws-cdk-lib/aws-events");
const logs = require("aws-cdk-lib/aws-logs");
class ContainerRuntimeSecurityStack extends aws_cdk_lib_1.Stack {
    constructor(scope, id, props) {
        super(scope, id, props);
        this.configureEnhancedScanning();
        this.createEventBridgeToLambda();
    }
    configureEnhancedScanning() {
        new custom_resources_1.AwsCustomResource(this, "ecrEnhancedScanning", {
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
            policy: custom_resources_1.AwsCustomResourcePolicy.fromStatements([
                new aws_iam_1.PolicyStatement({
                    actions: [
                        "iam:CreateServiceLinkedRole",
                        "inspector2:Enable",
                        "ecr:PutRegistryScanningConfiguration",
                    ],
                    resources: custom_resources_1.AwsCustomResourcePolicy.ANY_RESOURCE,
                }),
            ]),
        }),
            new custom_resources_1.AwsCustomResource(this, "inspectorEcrConfiguration", {
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
                policy: custom_resources_1.AwsCustomResourcePolicy.fromStatements([
                    new aws_iam_1.PolicyStatement({
                        actions: [
                            "iam:CreateServiceLinkedRole",
                            // "inspector2:listMembers",
                            "inspector2:UpdateConfiguration",
                        ],
                        resources: custom_resources_1.AwsCustomResourcePolicy.ANY_RESOURCE,
                    }),
                ]),
            });
    }
    createEventBridgeToLambda() {
        const constructProps = {
            lambdaFunctionProps: {
                code: lambda.Code.fromAsset(path.join(__dirname, "../", "lambdas", "CheckEcs"), { exclude: ["*.ts", "*.d.ts"] }),
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
                    resources: events.Match.prefix("arn:aws:ecr")
                },
                enabled: true,
            },
        };
        const ebl = new aws_eventbridge_lambda_1.EventbridgeToLambda(this, "vulnerable-ecr-image-found-lambda", constructProps);
    }
}
exports.ContainerRuntimeSecurityStack = ContainerRuntimeSecurityStack;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiQ29udGFpbmVyUnVudGltZVNlY3VyaXR5U3RhY2suanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyJDb250YWluZXJSdW50aW1lU2VjdXJpdHlTdGFjay50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFBQSw2Q0FBeUU7QUFFekUsbUVBR3NDO0FBQ3RDLGlEQUFzRDtBQUN0RCw2RkFHMEQ7QUFDMUQsNkJBQThCO0FBQzlCLGlEQUFpRDtBQUNqRCwyQ0FBMkM7QUFDM0MsaURBQWlEO0FBRWpELDZDQUE2QztBQUU3QyxNQUFhLDZCQUE4QixTQUFRLG1CQUFLO0lBQ3RELFlBQVksS0FBZ0IsRUFBRSxFQUFVLEVBQUUsS0FBa0I7UUFDMUQsS0FBSyxDQUFDLEtBQUssRUFBRSxFQUFFLEVBQUUsS0FBSyxDQUFDLENBQUM7UUFFeEIsSUFBSSxDQUFDLHlCQUF5QixFQUFFLENBQUM7UUFDakMsSUFBSSxDQUFDLHlCQUF5QixFQUFFLENBQUM7SUFDbkMsQ0FBQztJQUVELHlCQUF5QjtRQUVyQixJQUFJLG9DQUFpQixDQUFDLElBQUksRUFBRSxxQkFBcUIsRUFBRTtZQUNqRCxRQUFRLEVBQUU7Z0JBQ1IsT0FBTyxFQUFFLEtBQUs7Z0JBQ2QsTUFBTSxFQUFFLGtDQUFrQztnQkFDMUMsa0JBQWtCLEVBQUUsRUFBRSxFQUFFLEVBQUUsa0NBQWtDLEVBQUU7Z0JBQzlELFVBQVUsRUFBRTtvQkFDVixLQUFLLEVBQUU7d0JBQ0w7NEJBQ0UsaUJBQWlCLEVBQUUsQ0FBQyxHQUFHLENBQUM7NEJBQ3hCLGFBQWEsRUFBRSxjQUFjO3lCQUM5QjtxQkFDRjtvQkFDRCxRQUFRLEVBQUUsVUFBVTtpQkFDckI7YUFDRjtZQUNELFFBQVEsRUFBRTtnQkFDUixPQUFPLEVBQUUsS0FBSztnQkFDZCxNQUFNLEVBQUUsa0NBQWtDO2dCQUMxQyxrQkFBa0IsRUFBRSxFQUFFLEVBQUUsRUFBRSxrQ0FBa0MsRUFBRTtnQkFDOUQsVUFBVSxFQUFFO29CQUNWLFFBQVEsRUFBRSxVQUFVO2lCQUNyQjthQUNGO1lBRUQsTUFBTSxFQUFFLDBDQUF1QixDQUFDLGNBQWMsQ0FBQztnQkFDN0MsSUFBSSx5QkFBZSxDQUFDO29CQUNsQixPQUFPLEVBQUU7d0JBQ1AsNkJBQTZCO3dCQUM3QixtQkFBbUI7d0JBQ25CLHNDQUFzQztxQkFDdkM7b0JBQ0QsU0FBUyxFQUFFLDBDQUF1QixDQUFDLFlBQVk7aUJBQ2hELENBQUM7YUFDSCxDQUFDO1NBQ0gsQ0FBQztZQUlGLElBQUksb0NBQWlCLENBQUMsSUFBSSxFQUFFLDJCQUEyQixFQUFFO2dCQUN2RCwwR0FBMEc7Z0JBQzFHLFFBQVEsRUFBRTtvQkFDUixPQUFPLEVBQUUsWUFBWTtvQkFDckIsTUFBTSxFQUFFLHFCQUFxQjtvQkFDN0Isa0JBQWtCLEVBQUUsRUFBRSxFQUFFLEVBQUUscUJBQXFCLEVBQUU7b0JBQ2pELFVBQVUsRUFBRTt3QkFDVixnQkFBZ0IsRUFBRTs0QkFDaEIsY0FBYyxFQUFFLFNBQVM7eUJBQzFCO3FCQUNGO2lCQUNGO2dCQUVELE1BQU0sRUFBRSwwQ0FBdUIsQ0FBQyxjQUFjLENBQUM7b0JBQzdDLElBQUkseUJBQWUsQ0FBQzt3QkFDbEIsT0FBTyxFQUFFOzRCQUNQLDZCQUE2Qjs0QkFDN0IsNEJBQTRCOzRCQUM1QixnQ0FBZ0M7eUJBQ2pDO3dCQUNELFNBQVMsRUFBRSwwQ0FBdUIsQ0FBQyxZQUFZO3FCQUNoRCxDQUFDO2lCQUNILENBQUM7YUFDSCxDQUFDLENBQUE7SUFDTixDQUFDO0lBRUQseUJBQXlCO1FBRXZCLE1BQU0sY0FBYyxHQUE2QjtZQUMvQyxtQkFBbUIsRUFBRTtnQkFDbkIsSUFBSSxFQUFFLE1BQU0sQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUN6QixJQUFJLENBQUMsSUFBSSxDQUFDLFNBQVMsRUFBRSxLQUFLLEVBQUUsU0FBUyxFQUFFLFVBQVUsQ0FBQyxFQUNsRCxFQUFFLE9BQU8sRUFBRSxDQUFDLE1BQU0sRUFBRSxRQUFRLENBQUMsRUFBRSxDQUNoQztnQkFDRCxXQUFXLEVBQUUsb0RBQW9EO2dCQUNqRSxZQUFZLEVBQUUsaUJBQWlCO2dCQUMvQixPQUFPLEVBQUUsTUFBTSxDQUFDLE9BQU8sQ0FBQyxXQUFXO2dCQUNuQyxPQUFPLEVBQUUsZUFBZTtnQkFDeEIsb0JBQW9CO2dCQUNwQiw0QkFBNEIsRUFBRSxDQUFDO2dCQUMvQixhQUFhLEVBQUU7b0JBQ2IsSUFBSSxHQUFHLENBQUMsZUFBZSxDQUFDO3dCQUN0QixTQUFTLEVBQUUsQ0FBQyxHQUFHLENBQUM7d0JBQ2hCLE9BQU8sRUFBRSxDQUFDLGtCQUFrQixFQUFFLGVBQWUsRUFBRSxtQkFBbUIsRUFBRSxzQkFBc0IsQ0FBQztxQkFDNUYsQ0FBQztpQkFDSDtnQkFDRCxZQUFZLEVBQUUsSUFBSSxDQUFDLGFBQWEsQ0FBQyxTQUFTO2FBQzNDO1lBRUQsY0FBYyxFQUFFO2dCQUNkLFFBQVEsRUFBRSwyQ0FBMkM7Z0JBQ3JELFlBQVksRUFBRTtvQkFDWixNQUFNLEVBQUUsQ0FBQyxnQkFBZ0IsQ0FBQztvQkFDMUIsVUFBVSxFQUFFLENBQUMsb0JBQW9CLENBQUM7b0JBQ2xDLFNBQVMsRUFBRyxNQUFNLENBQUMsS0FBSyxDQUFDLE1BQU0sQ0FBQyxhQUFhLENBQUM7aUJBQy9DO2dCQUNELE9BQU8sRUFBRSxJQUFJO2FBQ2Q7U0FDRixDQUFDO1FBRUYsTUFBTSxHQUFHLEdBQUcsSUFBSSw0Q0FBbUIsQ0FDakMsSUFBSSxFQUNKLG1DQUFtQyxFQUNuQyxjQUFjLENBQ2YsQ0FBQztJQUNKLENBQUM7Q0FDRjtBQWxIRCxzRUFrSEMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBEdXJhdGlvbiwgU3RhY2ssIFN0YWNrUHJvcHMsIFJlbW92YWxQb2xpY3kgfSBmcm9tIFwiYXdzLWNkay1saWJcIjtcbmltcG9ydCB7IENvbnN0cnVjdCB9IGZyb20gXCJjb25zdHJ1Y3RzXCI7XG5pbXBvcnQge1xuICBBd3NDdXN0b21SZXNvdXJjZSxcbiAgQXdzQ3VzdG9tUmVzb3VyY2VQb2xpY3ksXG59IGZyb20gXCJhd3MtY2RrLWxpYi9jdXN0b20tcmVzb3VyY2VzXCI7XG5pbXBvcnQgeyBQb2xpY3lTdGF0ZW1lbnQgfSBmcm9tIFwiYXdzLWNkay1saWIvYXdzLWlhbVwiO1xuaW1wb3J0IHtcbiAgRXZlbnRicmlkZ2VUb0xhbWJkYSxcbiAgRXZlbnRicmlkZ2VUb0xhbWJkYVByb3BzLFxufSBmcm9tIFwiQGF3cy1zb2x1dGlvbnMtY29uc3RydWN0cy9hd3MtZXZlbnRicmlkZ2UtbGFtYmRhXCI7XG5pbXBvcnQgcGF0aCA9IHJlcXVpcmUoXCJwYXRoXCIpO1xuaW1wb3J0ICogYXMgbGFtYmRhIGZyb20gXCJhd3MtY2RrLWxpYi9hd3MtbGFtYmRhXCI7XG5pbXBvcnQgKiBhcyBpYW0gZnJvbSBcImF3cy1jZGstbGliL2F3cy1pYW1cIjtcbmltcG9ydCAqIGFzIGV2ZW50cyBmcm9tIFwiYXdzLWNkay1saWIvYXdzLWV2ZW50c1wiO1xuaW1wb3J0IHsgTGFtYmRhRnVuY3Rpb25Qcm9wcyB9IGZyb20gXCJhd3MtY2RrLWxpYi9hd3MtZXZlbnRzLXRhcmdldHNcIjtcbmltcG9ydCAqIGFzIGxvZ3MgZnJvbSBcImF3cy1jZGstbGliL2F3cy1sb2dzXCI7XG5cbmV4cG9ydCBjbGFzcyBDb250YWluZXJSdW50aW1lU2VjdXJpdHlTdGFjayBleHRlbmRzIFN0YWNrIHtcbiAgY29uc3RydWN0b3Ioc2NvcGU6IENvbnN0cnVjdCwgaWQ6IHN0cmluZywgcHJvcHM/OiBTdGFja1Byb3BzKSB7XG4gICAgc3VwZXIoc2NvcGUsIGlkLCBwcm9wcyk7XG5cbiAgICB0aGlzLmNvbmZpZ3VyZUVuaGFuY2VkU2Nhbm5pbmcoKTtcbiAgICB0aGlzLmNyZWF0ZUV2ZW50QnJpZGdlVG9MYW1iZGEoKTtcbiAgfVxuXG4gIGNvbmZpZ3VyZUVuaGFuY2VkU2Nhbm5pbmcoKSB7XG4gICAgXG4gICAgICBuZXcgQXdzQ3VzdG9tUmVzb3VyY2UodGhpcywgXCJlY3JFbmhhbmNlZFNjYW5uaW5nXCIsIHtcbiAgICAgICAgb25DcmVhdGU6IHtcbiAgICAgICAgICBzZXJ2aWNlOiBcIkVDUlwiLFxuICAgICAgICAgIGFjdGlvbjogXCJwdXRSZWdpc3RyeVNjYW5uaW5nQ29uZmlndXJhdGlvblwiLFxuICAgICAgICAgIHBoeXNpY2FsUmVzb3VyY2VJZDogeyBpZDogXCJwdXRSZWdpc3RyeVNjYW5uaW5nQ29uZmlndXJhdGlvblwiIH0sXG4gICAgICAgICAgcGFyYW1ldGVyczoge1xuICAgICAgICAgICAgcnVsZXM6IFtcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJlcG9zaXRvcnlGaWx0ZXJzOiBbXCIqXCJdLFxuICAgICAgICAgICAgICAgIHNjYW5GcmVxdWVuY3k6IFwiU0NBTl9PTl9QVVNIXCIsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgICAgc2NhblR5cGU6IFwiRU5IQU5DRURcIixcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICBvblVwZGF0ZToge1xuICAgICAgICAgIHNlcnZpY2U6IFwiRUNSXCIsXG4gICAgICAgICAgYWN0aW9uOiBcInB1dFJlZ2lzdHJ5U2Nhbm5pbmdDb25maWd1cmF0aW9uXCIsXG4gICAgICAgICAgcGh5c2ljYWxSZXNvdXJjZUlkOiB7IGlkOiBcInB1dFJlZ2lzdHJ5U2Nhbm5pbmdDb25maWd1cmF0aW9uXCIgfSxcbiAgICAgICAgICBwYXJhbWV0ZXJzOiB7XG4gICAgICAgICAgICBzY2FuVHlwZTogXCJFTkhBTkNFRFwiLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIFxuICAgICAgICBwb2xpY3k6IEF3c0N1c3RvbVJlc291cmNlUG9saWN5LmZyb21TdGF0ZW1lbnRzKFtcbiAgICAgICAgICBuZXcgUG9saWN5U3RhdGVtZW50KHtcbiAgICAgICAgICAgIGFjdGlvbnM6IFtcbiAgICAgICAgICAgICAgXCJpYW06Q3JlYXRlU2VydmljZUxpbmtlZFJvbGVcIixcbiAgICAgICAgICAgICAgXCJpbnNwZWN0b3IyOkVuYWJsZVwiLFxuICAgICAgICAgICAgICBcImVjcjpQdXRSZWdpc3RyeVNjYW5uaW5nQ29uZmlndXJhdGlvblwiLFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICAgIHJlc291cmNlczogQXdzQ3VzdG9tUmVzb3VyY2VQb2xpY3kuQU5ZX1JFU09VUkNFLFxuICAgICAgICAgIH0pLFxuICAgICAgICBdKSxcbiAgICAgIH0pLFxuXG5cblxuICAgICAgbmV3IEF3c0N1c3RvbVJlc291cmNlKHRoaXMsIFwiaW5zcGVjdG9yRWNyQ29uZmlndXJhdGlvblwiLCB7XG4gICAgICAgIC8vIGluc3RhbGxMYXRlc3RBd3NTZGs6IHRydWUsIC8vPC0gbXVzdCBiZSB0dXJuZWQgb24gZm9yIGZpcnN0IGRlcGxveW1lbnQsIGFmdGVyIHRoYXQgY2FuIGJlIGNvbW1lbnRlZCBvdXRcbiAgICAgICAgb25VcGRhdGU6IHtcbiAgICAgICAgICBzZXJ2aWNlOiBcIkluc3BlY3RvcjJcIixcbiAgICAgICAgICBhY3Rpb246IFwidXBkYXRlQ29uZmlndXJhdGlvblwiLFxuICAgICAgICAgIHBoeXNpY2FsUmVzb3VyY2VJZDogeyBpZDogXCJ1cGRhdGVDb25maWd1cmF0aW9uXCIgfSxcbiAgICAgICAgICBwYXJhbWV0ZXJzOiB7XG4gICAgICAgICAgICBlY3JDb25maWd1cmF0aW9uOiB7XG4gICAgICAgICAgICAgIHJlc2NhbkR1cmF0aW9uOiBcIkRBWVNfMzBcIiwgXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIFxuICAgICAgICBwb2xpY3k6IEF3c0N1c3RvbVJlc291cmNlUG9saWN5LmZyb21TdGF0ZW1lbnRzKFtcbiAgICAgICAgICBuZXcgUG9saWN5U3RhdGVtZW50KHtcbiAgICAgICAgICAgIGFjdGlvbnM6IFtcbiAgICAgICAgICAgICAgXCJpYW06Q3JlYXRlU2VydmljZUxpbmtlZFJvbGVcIixcbiAgICAgICAgICAgICAgLy8gXCJpbnNwZWN0b3IyOmxpc3RNZW1iZXJzXCIsXG4gICAgICAgICAgICAgIFwiaW5zcGVjdG9yMjpVcGRhdGVDb25maWd1cmF0aW9uXCIsXG4gICAgICAgICAgICBdLFxuICAgICAgICAgICAgcmVzb3VyY2VzOiBBd3NDdXN0b21SZXNvdXJjZVBvbGljeS5BTllfUkVTT1VSQ0UsXG4gICAgICAgICAgfSksXG4gICAgICAgIF0pLFxuICAgICAgfSlcbiAgfVxuXG4gIGNyZWF0ZUV2ZW50QnJpZGdlVG9MYW1iZGEoKSB7XG5cbiAgICBjb25zdCBjb25zdHJ1Y3RQcm9wczogRXZlbnRicmlkZ2VUb0xhbWJkYVByb3BzID0ge1xuICAgICAgbGFtYmRhRnVuY3Rpb25Qcm9wczoge1xuICAgICAgICBjb2RlOiBsYW1iZGEuQ29kZS5mcm9tQXNzZXQoXG4gICAgICAgICAgcGF0aC5qb2luKF9fZGlybmFtZSwgXCIuLi9cIiwgXCJsYW1iZGFzXCIsIFwiQ2hlY2tFY3NcIiksXG4gICAgICAgICAgeyBleGNsdWRlOiBbXCIqLnRzXCIsIFwiKi5kLnRzXCJdIH1cbiAgICAgICAgKSxcbiAgICAgICAgZGVzY3JpcHRpb246IFwiQ2hlY2sgRUNTIGZvciBmb3VuZCB2dWxuZXJhYmlsdHkgaW4gcnVubmluZyBpbWFnZXNcIixcbiAgICAgICAgZnVuY3Rpb25OYW1lOiBcIkNoZWNrRUNTLUxhbWJkYVwiLFxuICAgICAgICBydW50aW1lOiBsYW1iZGEuUnVudGltZS5OT0RFSlNfMThfWCxcbiAgICAgICAgaGFuZGxlcjogXCJpbmRleC5oYW5kbGVyXCIsXG4gICAgICAgIC8vIHJvbGU6IGxhbWJkYVJvbGUsXG4gICAgICAgIHJlc2VydmVkQ29uY3VycmVudEV4ZWN1dGlvbnM6IDEsXG4gICAgICAgIGluaXRpYWxQb2xpY3k6IFtcbiAgICAgICAgICBuZXcgaWFtLlBvbGljeVN0YXRlbWVudCh7XG4gICAgICAgICAgICByZXNvdXJjZXM6IFtcIipcIl0sXG4gICAgICAgICAgICBhY3Rpb25zOiBbXCJlY3M6TGlzdENsdXN0ZXJzXCIsIFwiZWNzOkxpc3RUYXNrc1wiLCBcImVjczpEZXNjcmliZVRhc2tzXCIsIFwiZWNzOkRlc2NyaWJlQ2x1c3RlcnNcIl0sXG4gICAgICAgICAgfSksXG4gICAgICAgIF0sXG4gICAgICAgIGxvZ1JldGVudGlvbjogbG9ncy5SZXRlbnRpb25EYXlzLk9ORV9NT05USCxcbiAgICAgIH0sXG5cbiAgICAgIGV2ZW50UnVsZVByb3BzOiB7XG4gICAgICAgIHJ1bGVOYW1lOiBcImVjci1lbmhhbmNlZC1zY2FubmluZy12dWxuZXJhYmlsaXR5LWZvdW5kXCIsXG4gICAgICAgIGV2ZW50UGF0dGVybjoge1xuICAgICAgICAgIHNvdXJjZTogW1wiYXdzLmluc3BlY3RvcjJcIl0sXG4gICAgICAgICAgZGV0YWlsVHlwZTogW1wiSW5zcGVjdG9yMiBGaW5kaW5nXCJdLFxuICAgICAgICAgIHJlc291cmNlczogIGV2ZW50cy5NYXRjaC5wcmVmaXgoXCJhcm46YXdzOmVjclwiKSBcbiAgICAgICAgfSxcbiAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgIH0sXG4gICAgfTtcblxuICAgIGNvbnN0IGVibCA9IG5ldyBFdmVudGJyaWRnZVRvTGFtYmRhKFxuICAgICAgdGhpcyxcbiAgICAgIFwidnVsbmVyYWJsZS1lY3ItaW1hZ2UtZm91bmQtbGFtYmRhXCIsXG4gICAgICBjb25zdHJ1Y3RQcm9wc1xuICAgICk7XG4gIH1cbn1cbiJdfQ==