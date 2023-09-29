import { App } from "aws-cdk-lib";
import { ContainerRuntimeSecurityStack } from "./stacks/ContainerRuntimeSecurityStack";

const app = new App()

const crsStack = new ContainerRuntimeSecurityStack(
    app, "ContainerRuntimeScanning"
)
