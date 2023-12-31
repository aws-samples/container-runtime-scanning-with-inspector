"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const aws_cdk_lib_1 = require("aws-cdk-lib");
const ContainerRuntimeSecurityStack_1 = require("./stacks/ContainerRuntimeSecurityStack");
const app = new aws_cdk_lib_1.App();
const crsStack = new ContainerRuntimeSecurityStack_1.ContainerRuntimeSecurityStack(app, "ContainerRuntimeScanning");
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibWFpbi5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIm1haW4udHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7QUFBQSw2Q0FBa0M7QUFDbEMsMEZBQXVGO0FBRXZGLE1BQU0sR0FBRyxHQUFHLElBQUksaUJBQUcsRUFBRSxDQUFBO0FBRXJCLE1BQU0sUUFBUSxHQUFHLElBQUksNkRBQTZCLENBQzlDLEdBQUcsRUFBRSwwQkFBMEIsQ0FDbEMsQ0FBQSIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IEFwcCB9IGZyb20gXCJhd3MtY2RrLWxpYlwiO1xuaW1wb3J0IHsgQ29udGFpbmVyUnVudGltZVNlY3VyaXR5U3RhY2sgfSBmcm9tIFwiLi9zdGFja3MvQ29udGFpbmVyUnVudGltZVNlY3VyaXR5U3RhY2tcIjtcblxuY29uc3QgYXBwID0gbmV3IEFwcCgpXG5cbmNvbnN0IGNyc1N0YWNrID0gbmV3IENvbnRhaW5lclJ1bnRpbWVTZWN1cml0eVN0YWNrKFxuICAgIGFwcCwgXCJDb250YWluZXJSdW50aW1lU2Nhbm5pbmdcIlxuKVxuIl19