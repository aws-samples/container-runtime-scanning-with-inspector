import { Stack, StackProps } from "aws-cdk-lib";
import { Construct } from "constructs";
export declare class ContainerRuntimeSecurityStack extends Stack {
    constructor(scope: Construct, id: string, props?: StackProps);
    configureEnhancedScanning(): void;
    createEventBridgeToLambda(): void;
}
