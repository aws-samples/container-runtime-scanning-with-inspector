import { Callback, EventBridgeEvent, Context } from "aws-lambda";
export declare const handler: (event: EventBridgeEvent<string, any>, context: Context, callback: Callback) => Promise<void>;
