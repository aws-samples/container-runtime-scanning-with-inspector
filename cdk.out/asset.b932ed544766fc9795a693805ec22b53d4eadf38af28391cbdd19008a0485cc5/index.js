"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.handler = void 0;
const client_ecs_1 = require("@aws-sdk/client-ecs");
const ecs = new client_ecs_1.ECSClient({});
const getListOfClusterARN = async () => {
    let clusterList = [];
    let nextToken;
    const input = {};
    const command = new client_ecs_1.ListClustersCommand(input);
    do {
        const response = await ecs.send(command);
        // console.log(`
        //     #############
        //     list of clusters:  ${JSON.stringify(response)}
        //     #############
        // `)
        if (response != undefined) {
            // return response.clusterArns!;
            // set next token here
            nextToken = response.nextToken;
            clusterList = clusterList.concat(response.clusterArns);
        }
    } while (nextToken);
    return clusterList;
};
// returns list of ALL task ARN from specified cluster
const listTasksFromClusterARN = async (clusterName) => {
    let taskList = [];
    let nextToken;
    do {
        const input = {
            cluster: clusterName,
        };
        const command = new client_ecs_1.ListTasksCommand(input);
        const response = await ecs.send(command);
        // console.log(`
        //   #############
        //   list tasks from cluster arn: ${response.taskArns}
        //   #############
        //   `);
        // return response.taskArns;
        if (response != undefined) {
            nextToken = response.nextToken;
            taskList = taskList.concat(response.taskArns);
        }
    } while (nextToken);
    return taskList;
};
// formats task ARN to ID
const formatTaskName = (taskARN) => {
    const indexOfLastSlash = taskARN.lastIndexOf("/");
    const taskName = taskARN.substring(indexOfLastSlash + 1);
    return taskName;
};
const getVulnerableDigestsPerARN = async (clusterARN) => {
    const taskList = await listTasksFromClusterARN(clusterARN);
    let vulnerableDigests = {};
    if (taskList != undefined) {
        const taskIdList = taskList.map((task) => formatTaskName(task));
        const input = {
            tasks: taskIdList,
            cluster: clusterARN,
        };
        const command = new client_ecs_1.DescribeTasksCommand(input);
        const response = await ecs.send(command);
        const listOfTasksFromResponse = response.tasks;
        if (listOfTasksFromResponse != undefined) {
            for (const task of listOfTasksFromResponse) {
                for (let n = 0; n < task.containers.length; n++) {
                    if (task.containers[n].taskArn in vulnerableDigests) {
                        vulnerableDigests[task.containers[n].taskArn].push(task.containers[n].imageDigest);
                    }
                    else {
                        vulnerableDigests[task.containers[n].taskArn] = [
                            task.containers[n].imageDigest,
                        ];
                    }
                }
            }
        }
        return vulnerableDigests;
    }
    return undefined;
};
// returns the name of the cluster or undefined if not found
const getClusterName = async (clusterARN) => {
    const input = {
        clusters: [clusterARN],
    };
    const command = new client_ecs_1.DescribeClustersCommand(input);
    const response = await ecs.send(command);
    if (response != undefined) {
        return response.clusters[0].clusterName;
    }
    return undefined;
};
// filters list of tasks to just vulnerable tasks
// try with just returning a tasklist
const getVulnerableTaskList = async (eventImageDigest, clusterARN) => {
    const vulnerableTaskList = [];
    const clusterName = await getClusterName(clusterARN);
    const taskList = await listTasksFromClusterARN(clusterARN);
    console.log(`The list of tasks: ${taskList.map((task) => formatTaskName(task))}`);
    // const input = {
    //   tasks: taskList.map((task)=>formatTaskName(task)),
    // };
    // const command = new DescribeTasksCommand(input);
    // const response = await ecs.send(command);
    // console.log(response);
    if (taskList === undefined) {
        console.log(`No ECS tasks found in cluster ${clusterName}`);
    }
    else {
        for (const task of taskList) {
            console.log(task);
            console.log(formatTaskName(task));
            if (formatTaskName(task) === eventImageDigest) {
                vulnerableTaskList.push(task);
            }
        }
        console.log(vulnerableTaskList);
        return vulnerableTaskList;
    }
    return undefined;
};
const compareDigests = (eventImageDigest, imageDigest) => {
    return eventImageDigest === imageDigest;
};
// takes list of vulnerable task ARN and eventimagedigest
// prints the container name along with the task ARN
const printLogMessage = async (listOfVulnerableTasks, eventImgDigest) => {
    if (listOfVulnerableTasks == undefined) {
        console.log("Vulnerable task list is undefined.");
    }
    else if (listOfVulnerableTasks.length === 0) {
        console.log(`No ECS tasks with vulnerable image ${eventImgDigest} found.`);
    }
    else {
        // for (const vulnDigest of listOfVulnerableTasks) {
        //   if (compareDigests(vulnDigest, eventImgDigest)) {
        //     console.log(
        //       `ECS task with vulnerable image ${eventImgDigest} found: ${vulnDigest}`
        //     );
        //     console.log(`${vulnDigest}`);
        //     // print the entire task description
        //   }
        // }
        const input = {
            tasks: listOfVulnerableTasks,
        };
        const command = new client_ecs_1.DescribeTasksCommand(input);
        const response = await ecs.send(command);
        for (const task of response.tasks) {
            for (const container of task.containers) {
                // print the task ARN
                console.log(`Container ${container.name} found with
                 vulnerable image ${eventImgDigest}. Refer to task ARN ${task.taskArn}`);
                // print the entire container information
                console.log(container);
            }
        }
    }
};
const handler = async function (event, context, callback) {
    // console.log(`
    // ###############
    // ${JSON.stringify(event)}
    // ###############
    // `)
    const eventImageARN = event.resources[0];
    // const eventImageDigest: string = event.detail.resources.awsEcrContainerImage.imageHash
    const eventImageARNDigestIndex = eventImageARN.lastIndexOf("/sha256:");
    const eventImageDigest = eventImageARN.slice(eventImageARNDigestIndex + 1); // added + 1 to remove the / in the string
    // console.log(`
    // ###############
    // This is the event image digest: ${eventImageDigest}
    // ###############
    // `);
    const clusterList = await getListOfClusterARN();
    for (const cluster of clusterList) {
        const vulnResources = await getVulnerableTaskList(eventImageDigest, cluster);
        printLogMessage(vulnResources, eventImageDigest);
    }
};
exports.handler = handler;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyJpbmRleC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFDQSxvREFNNkI7QUFFN0IsTUFBTSxHQUFHLEdBQUcsSUFBSSxzQkFBUyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0FBRTlCLE1BQU0sbUJBQW1CLEdBQUcsS0FBSyxJQUF1QixFQUFFO0lBQ3hELElBQUksV0FBVyxHQUFhLEVBQUUsQ0FBQztJQUMvQixJQUFJLFNBQTZCLENBQUM7SUFFbEMsTUFBTSxLQUFLLEdBQUcsRUFBRSxDQUFDO0lBQ2pCLE1BQU0sT0FBTyxHQUFHLElBQUksZ0NBQW1CLENBQUMsS0FBSyxDQUFDLENBQUM7SUFDL0MsR0FBRztRQUNELE1BQU0sUUFBUSxHQUFHLE1BQU0sR0FBRyxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsQ0FBQztRQUN6QyxnQkFBZ0I7UUFDaEIsb0JBQW9CO1FBQ3BCLHFEQUFxRDtRQUNyRCxvQkFBb0I7UUFDcEIsS0FBSztRQUNMLElBQUksUUFBUSxJQUFJLFNBQVMsRUFBRTtZQUN6QixnQ0FBZ0M7WUFDaEMsc0JBQXNCO1lBQ3RCLFNBQVMsR0FBRyxRQUFRLENBQUMsU0FBUyxDQUFDO1lBQy9CLFdBQVcsR0FBRyxXQUFXLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxXQUFZLENBQUMsQ0FBQztTQUN6RDtLQUNGLFFBQVEsU0FBUyxFQUFFO0lBQ3BCLE9BQU8sV0FBVyxDQUFDO0FBQ3JCLENBQUMsQ0FBQztBQUNGLHNEQUFzRDtBQUN0RCxNQUFNLHVCQUF1QixHQUFHLEtBQUssRUFBRSxXQUFtQixFQUFFLEVBQUU7SUFDNUQsSUFBSSxRQUFRLEdBQWEsRUFBRSxDQUFDO0lBQzVCLElBQUksU0FBNkIsQ0FBQztJQUVsQyxHQUFHO1FBQ0QsTUFBTSxLQUFLLEdBQUc7WUFDWixPQUFPLEVBQUUsV0FBVztTQUNyQixDQUFDO1FBQ0YsTUFBTSxPQUFPLEdBQUcsSUFBSSw2QkFBZ0IsQ0FBQyxL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QkFDeEMscUJBQXFCO2dCQUNyQixPQUFPLENBQUMsR0FBRyxDQUFDLGFBQWEsU0FBUyxDQUFDLElBQUk7b0NBQ1gsY0FBYyx1QkFBdUIsSUFBSSxDQUFDLE9BQU8sRUFBRSxDQUFDLENBQUM7Z0JBQ2pGLHlDQUF5QztnQkFDekMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxTQUFTLENBQUMsQ0FBQzthQUN4QjtTQUNGO0tBQ0Y7QUFDSCxDQUFDLENBQUM7QUFFSyxNQUFNLE9BQU8sR0FBRyxLQUFLLFdBQzFCLEtBQW9DLEVBQ3BDLE9BQWdCLEVBQ2hCLFFBQWtCO0lBRWxCLGdCQUFnQjtJQUNoQixrQkFBa0I7SUFDbEIsMkJBQTJCO0lBQzNCLGtCQUFrQjtJQUNsQixLQUFLO0lBQ0wsTUFBTSxhQUFhLEdBQVcsS0FBSyxDQUFDLFNBQVMsQ0FBQyxDQUFDLENBQUMsQ0FBQztJQUNqRCx5RkFBeUY7SUFDekYsTUFBTSx3QkFBd0IsR0FBRyxhQUFhLENBQUMsV0FBVyxDQUFDLFVBQVUsQ0FBQyxDQUFDO0lBQ3ZFLE1BQU0sZ0JBQWdCLEdBQUcsYUFBYSxDQUFDLEtBQUssQ0FBQyx3QkFBd0IsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFDLDBDQUEwQztJQUN0SCxnQkFBZ0I7SUFDaEIsa0JBQWtCO0lBQ2xCLHNEQUFzRDtJQUN0RCxrQkFBa0I7SUFDbEIsTUFBTTtJQUVOLE1BQU0sV0FBVyxHQUFHLE1BQU0sbUJBQW1CLEVBQUUsQ0FBQztJQUNoRCxLQUFLLE1BQU0sT0FBTyxJQUFJLFdBQVcsRUFBRTtRQUNqQyxNQUFNLGFBQWEsR0FBRyxNQUFNLHFCQUFxQixDQUMvQyxnQkFBZ0IsRUFDaEIsT0FBTyxDQUNSLENBQUM7UUFDRixlQUFlLENBQUMsYUFBYSxFQUFFLGdCQUFnQixDQUFDLENBQUM7S0FDbEQ7QUFDSCxDQUFDLENBQUM7QUE1QlcsUUFBQSxPQUFPLFdBNEJsQiIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IENhbGxiYWNrLCBFdmVudEJyaWRnZUV2ZW50LCBDb250ZXh0IH0gZnJvbSBcImF3cy1sYW1iZGFcIjtcbmltcG9ydCB7XG4gIEVDU0NsaWVudCxcbiAgTGlzdENsdXN0ZXJzQ29tbWFuZCxcbiAgTGlzdFRhc2tzQ29tbWFuZCxcbiAgRGVzY3JpYmVUYXNrc0NvbW1hbmQsXG4gIERlc2NyaWJlQ2x1c3RlcnNDb21tYW5kLFxufSBmcm9tIFwiQGF3cy1zZGsvY2xpZW50LWVjc1wiO1xuXG5jb25zdCBlY3MgPSBuZXcgRUNTQ2xpZW50KHt9KTtcblxuY29uc3QgZ2V0TGlzdE9mQ2x1c3RlckFSTiA9IGFzeW5jICgpOiBQcm9taXNlPHN0cmluZ1tdPiA9PiB7XG4gIGxldCBjbHVzdGVyTGlzdDogc3RyaW5nW10gPSBbXTtcbiAgbGV0IG5leHRUb2tlbjogc3RyaW5nIHwgdW5kZWZpbmVkO1xuXG4gIGNvbnN0IGlucHV0ID0ge307XG4gIGNvbnN0IGNvbW1hbmQgPSBuZXcgTGlzdENsdXN0ZXJzQ29tbWFuZChpbnB1dCk7XG4gIGRvIHtcbiAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGVjcy5zZW5kKGNvbW1hbmQpO1xuICAgIC8vIGNvbnNvbGUubG9nKGBcbiAgICAvLyAgICAgIyMjIyMjIyMjIyMjI1xuICAgIC8vICAgICBsaXN0IG9mIGNsdXN0ZXJzOiAgJHtKU09OLnN0cmluZ2lmeShyZXNwb25zZSl9XG4gICAgLy8gICAgICMjIyMjIyMjIyMjIyNcbiAgICAvLyBgKVxuICAgIGlmIChyZXNwb25zZSAhPSB1bmRlZmluZWQpIHtcbiAgICAgIC8vIHJldHVybiByZXNwb25zZS5jbHVzdGVyQXJucyE7XG4gICAgICAvLyBzZXQgbmV4dCB0b2tlbiBoZXJlXG4gICAgICBuZXh0VG9rZW4gPSByZXNwb25zZS5uZXh0VG9rZW47XG4gICAgICBjbHVzdGVyTGlzdCA9IGNsdXN0ZXJMaXN0LmNvbmNhdChyZXNwb25zZS5jbHVzdGVyQXJucyEpO1xuICAgIH1cbiAgfSB3aGlsZSAobmV4dFRva2VuKTtcbiAgcmV0dXJuIGNsdXN0ZXJMaXN0O1xufTtcbi8vIHJldHVybnMgbGlzdCBvZiBBTEwgdGFzayBBUk4gZnJvbSBzcGVjaWZpZWQgY2x1c3RlclxuY29uc3QgbGlzdFRhc2tzRnJvbUNsdXN0ZXJBUk4gPSBhc3luYyAoY2x1c3Rlck5hbWU6IHN0cmluZykgPT4ge1xuICBsZXQgdGFza0xpc3Q6IHN0cmluZ1tdID0gW107XG4gIGxldCBuZXh0VG9rZW46IHN0cmluZyB8IHVuZGVmaW5lZDtcblxuICBkbyB7XG4gICAgY29uc3QgaW5wdXQgPSB7XG4gICAgICBjbHVzdGVyOiBjbHVzdGVyTmFtZSxcbiAgICB9O1xuICAgIGNvbnN0IGNvbW1hbmQgPSBuZXcgTGlzdFRhc2tzQ29tbWFuZChpbnB1dCk7XG4gICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBlY3Muc2VuZChjb21tYW5kKTtcbiAgICAvLyBjb25zb2xlLmxvZyhgXG4gICAgLy8gICAjIyMjIyMjIyMjIyMjXG4gICAgLy8gICBsaXN0IHRhc2tzIGZyb20gY2x1c3RlciBhcm46ICR7cmVzcG9uc2UudGFza0FybnN9XG4gICAgLy8gICAjIyMjIyMjIyMjIyMjXG4gICAgLy8gICBgKTtcbiAgICAvLyByZXR1cm4gcmVzcG9uc2UudGFza0FybnM7XG4gICAgaWYgKHJlc3BvbnNlICE9IHVuZGVmaW5lZCkge1xuICAgICAgbmV4dFRva2VuID0gcmVzcG9uc2UubmV4dFRva2VuO1xuICAgICAgdGFza0xpc3QgPSB0YXNrTGlzdC5jb25jYXQocmVzcG9uc2UudGFza0FybnMhKTtcbiAgICB9XG4gIH0gd2hpbGUgKG5leHRUb2tlbik7XG4gIHJldHVybiB0YXNrTGlzdDtcbn07XG5cbi8vIGZvcm1hdHMgdGFzayBBUk4gdG8gSURcbmNvbnN0IGZvcm1hdFRhc2tOYW1lID0gKHRhc2tBUk46IHN0cmluZyk6IHN0cmluZyA9PiB7XG4gIGNvbnN0IGluZGV4T2ZMYXN0U2xhc2ggPSB0YXNrQVJOLmxhc3RJbmRleE9mKFwiL1wiKTtcbiAgY29uc3QgdGFza05hbWUgPSB0YXNrQVJOLnN1YnN0cmluZyhpbmRleE9mTGFzdFNsYXNoICsgMSk7XG4gIHJldHVybiB0YXNrTmFtZTtcbn07XG5cbmNvbnN0IGdldFZ1bG5lcmFibGVEaWdlc3RzUGVyQVJOID0gYXN5bmMgKGNsdXN0ZXJBUk46IHN0cmluZyk6IFByb21pc2U8YW55PiA9PiB7XG4gIGNvbnN0IHRhc2tMaXN0ID0gYXdhaXQgbGlzdFRhc2tzRnJvbUNsdXN0ZXJBUk4oY2x1c3RlckFSTik7XG4gIGxldCB2dWxuZXJhYmxlRGlnZXN0czogeyBba2V5OiBzdHJpbmddOiBzdHJpbmdbXSB9ID0ge307XG4gIGlmICh0YXNrTGlzdCAhPSB1bmRlZmluZWQpIHtcbiAgICBjb25zdCB0YXNrSWRMaXN0ID0gdGFza0xpc3QubWFwKCh0YXNrOiBzdHJpbmcpID0+IGZvcm1hdFRhc2tOYW1lKHRhc2spKTtcbiAgICBjb25zdCBpbnB1dCA9IHtcbiAgICAgIHRhc2tzOiB0YXNrSWRMaXN0LFxuICAgICAgY2x1c3RlcjogY2x1c3RlckFSTixcbiAgICB9O1xuICAgIGNvbnN0IGNvbW1hbmQgPSBuZXcgRGVzY3JpYmVUYXNrc0NvbW1hbmQoaW5wdXQpO1xuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4gICAgY29uc3QgbGlzdE9mVGFza3NGcm9tUmVzcG9uc2UgPSByZXNwb25zZS50YXNrcztcbiAgICBpZiAobGlzdE9mVGFza3NGcm9tUmVzcG9uc2UgIT0gdW5kZWZpbmVkKSB7XG4gICAgICBmb3IgKGNvbnN0IHRhc2sgb2YgbGlzdE9mVGFza3NGcm9tUmVzcG9uc2UpIHtcbiAgICAgICAgZm9yIChsZXQgbiA9IDA7IG4gPCB0YXNrLmNvbnRhaW5lcnMhLmxlbmd0aDsgbisrKSB7XG4gICAgICAgICAgaWYgKHRhc2suY29udGFpbmVycyFbbl0udGFza0FybiEgaW4gdnVsbmVyYWJsZURpZ2VzdHMpIHtcbiAgICAgICAgICAgIHZ1bG5lcmFibGVEaWdlc3RzW3Rhc2suY29udGFpbmVycyFbbl0udGFza0FybiFdLnB1c2goXG4gICAgICAgICAgICAgIHRhc2suY29udGFpbmVycyFbbl0uaW1hZ2VEaWdlc3QhXG4gICAgICAgICAgICApO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB2dWxuZXJhYmxlRGlnZXN0c1t0YXNrLmNvbnRhaW5lcnMhW25dLnRhc2tBcm4hXSA9IFtcbiAgICAgICAgICAgICAgdGFzay5jb250YWluZXJzIVtuXS5pbWFnZURpZ2VzdCEsXG4gICAgICAgICAgICBdO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gdnVsbmVyYWJsZURpZ2VzdHM7XG4gIH1cbiAgcmV0dXJuIHVuZGVmaW5lZDtcbn07XG5cbi8vIHJldHVybnMgdGhlIG5hbWUgb2YgdGhlIGNsdXN0ZXIgb3IgdW5kZWZpbmVkIGlmIG5vdCBmb3VuZFxuY29uc3QgZ2V0Q2x1c3Rlck5hbWUgPSBhc3luYyAoXG4gIGNsdXN0ZXJBUk46IHN0cmluZ1xuKTogUHJvbWlzZTxzdHJpbmcgfCB1bmRlZmluZWQ+ID0+IHtcbiAgY29uc3QgaW5wdXQgPSB7XG4gICAgY2x1c3RlcnM6IFtjbHVzdGVyQVJOXSxcbiAgfTtcbiAgY29uc3QgY29tbWFuZCA9IG5ldyBEZXNjcmliZUNsdXN0ZXJzQ29tbWFuZChpbnB1dCk7XG4gIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4gIGlmIChyZXNwb25zZSAhPSB1bmRlZmluZWQpIHtcbiAgICByZXR1cm4gcmVzcG9uc2UuY2x1c3RlcnMhWzBdLmNsdXN0ZXJOYW1lITtcbiAgfVxuICByZXR1cm4gdW5kZWZpbmVkO1xufTtcblxuLy8gZmlsdGVycyBsaXN0IG9mIHRhc2tzIHRvIGp1c3QgdnVsbmVyYWJsZSB0YXNrc1xuLy8gdHJ5IHdpdGgganVzdCByZXR1cm5pbmcgYSB0YXNrbGlzdFxuY29uc3QgZ2V0VnVsbmVyYWJsZVRhc2tMaXN0ID0gYXN5bmMgKFxuICBldmVudEltYWdlRGlnZXN0OiBzdHJpbmcsXG4gIGNsdXN0ZXJBUk46IHN0cmluZ1xuKTogUHJvbWlzZTxzdHJpbmdbXSB8IHVuZGVmaW5lZD4gPT4ge1xuICBjb25zdCB2dWxuZXJhYmxlVGFza0xpc3Q6IHN0cmluZ1tdID0gW107XG4gIGNvbnN0IGNsdXN0ZXJOYW1lID0gYXdhaXQgZ2V0Q2x1c3Rlck5hbWUoY2x1c3RlckFSTik7XG4gIGNvbnN0IHRhc2tMaXN0ID0gYXdhaXQgbGlzdFRhc2tzRnJvbUNsdXN0ZXJBUk4oY2x1c3RlckFSTik7XG4gIGNvbnNvbGUubG9nKGBUaGUgbGlzdCBvZiB0YXNrczogJHt0YXNrTGlzdC5tYXAoKHRhc2spPT5mb3JtYXRUYXNrTmFtZSh0YXNrKSl9YClcbiAgLy8gY29uc3QgaW5wdXQgPSB7XG4gIC8vICAgdGFza3M6IHRhc2tMaXN0Lm1hcCgodGFzayk9PmZvcm1hdFRhc2tOYW1lKHRhc2spKSxcbiAgLy8gfTtcbiAgLy8gY29uc3QgY29tbWFuZCA9IG5ldyBEZXNjcmliZVRhc2tzQ29tbWFuZChpbnB1dCk7XG4gIC8vIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4gIC8vIGNvbnNvbGUubG9nKHJlc3BvbnNlKTtcbiAgaWYgKHRhc2tMaXN0ID09PSB1bmRlZmluZWQpIHtcbiAgICBjb25zb2xlLmxvZyhgTm8gRUNTIHRhc2tzIGZvdW5kIGluIGNsdXN0ZXIgJHtjbHVzdGVyTmFtZX1gKTtcbiAgfSBlbHNlIHtcbiAgICBmb3IgKGNvbnN0IHRhc2sgb2YgdGFza0xpc3QpIHtcbiAgICAgIGNvbnNvbGUubG9nKHRhc2spO1xuICAgICAgY29uc29sZS5sb2coZm9ybWF0VGFza05hbWUodGFzaykpO1xuICAgICAgaWYgKGZvcm1hdFRhc2tOYW1lKHRhc2spID09PSBldmVudEltYWdlRGlnZXN0KSB7XG4gICAgICAgIHZ1bG5lcmFibGVUYXNrTGlzdC5wdXNoKHRhc2spO1xuICAgICAgfVxuICAgIH1cbiAgICBjb25zb2xlLmxvZyh2dWxuZXJhYmxlVGFza0xpc3QpO1xuICAgIHJldHVybiB2dWxuZXJhYmxlVGFza0xpc3Q7XG4gIH1cbiAgcmV0dXJuIHVuZGVmaW5lZDtcbn07XG5cbmNvbnN0IGNvbXBhcmVEaWdlc3RzID0gKFxuICBldmVudEltYWdlRGlnZXN0OiBzdHJpbmcsXG4gIGltYWdlRGlnZXN0OiBzdHJpbmdcbik6IGJvb2xlYW4gPT4ge1xuICByZXR1cm4gZXZlbnRJbWFnZURpZ2VzdCA9PT0gaW1hZ2VEaWdlc3Q7XG59O1xuXG4vLyB0YWtlcyBsaXN0IG9mIHZ1bG5lcmFibGUgdGFzayBBUk4gYW5kIGV2ZW50aW1hZ2VkaWdlc3Rcbi8vIHByaW50cyB0aGUgY29udGFpbmVyIG5hbWUgYWxvbmcgd2l0aCB0aGUgdGFzayBBUk5cbmNvbnN0IHByaW50TG9nTWVzc2FnZSA9IGFzeW5jIChcbiAgbGlzdE9mVnVsbmVyYWJsZVRhc2tzOiBzdHJpbmdbXSB8IHVuZGVmaW5lZCxcbiAgZXZlbnRJbWdEaWdlc3Q6IHN0cmluZ1xuKSA9PiB7XG4gIGlmIChsaXN0T2ZWdWxuZXJhYmxlVGFza3MgPT0gdW5kZWZpbmVkKSB7XG4gICAgY29uc29sZS5sb2coXCJWdWxuZXJhYmxlIHRhc2sgbGlzdCBpcyB1bmRlZmluZWQuXCIpO1xuICB9IGVsc2UgaWYgKGxpc3RPZlZ1bG5lcmFibGVUYXNrcy5sZW5ndGggPT09IDApIHtcbiAgICBjb25zb2xlLmxvZyhgTm8gRUNTIHRhc2tzIHdpdGggdnVsbmVyYWJsZSBpbWFnZSAke2V2ZW50SW1nRGlnZXN0fSBmb3VuZC5gKTtcbiAgfSBlbHNlIHtcbiAgICAvLyBmb3IgKGNvbnN0IHZ1bG5EaWdlc3Qgb2YgbGlzdE9mVnVsbmVyYWJsZVRhc2tzKSB7XG4gICAgLy8gICBpZiAoY29tcGFyZURpZ2VzdHModnVsbkRpZ2VzdCwgZXZlbnRJbWdEaWdlc3QpKSB7XG4gICAgLy8gICAgIGNvbnNvbGUubG9nKFxuICAgIC8vICAgICAgIGBFQ1MgdGFzayB3aXRoIHZ1bG5lcmFibGUgaW1hZ2UgJHtldmVudEltZ0RpZ2VzdH0gZm91bmQ6ICR7dnVsbkRpZ2VzdH1gXG4gICAgLy8gICAgICk7XG4gICAgLy8gICAgIGNvbnNvbGUubG9nKGAke3Z1bG5EaWdlc3R9YCk7XG4gICAgLy8gICAgIC8vIHByaW50IHRoZSBlbnRpcmUgdGFzayBkZXNjcmlwdGlvblxuICAgIC8vICAgfVxuICAgIC8vIH1cbiAgICBjb25zdCBpbnB1dCA9IHtcbiAgICAgIHRhc2tzOiBsaXN0T2ZWdWxuZXJhYmxlVGFza3MsXG4gICAgfTtcbiAgICBjb25zdCBjb21tYW5kID0gbmV3IERlc2NyaWJlVGFza3NDb21tYW5kKGlucHV0KTtcbiAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGVjcy5zZW5kKGNvbW1hbmQpO1xuICAgIGZvciAoY29uc3QgdGFzayBvZiByZXNwb25zZS50YXNrcyEpIHtcbiAgICAgIGZvciAoY29uc3QgY29udGFpbmVyIG9mIHRhc2suY29udGFpbmVycyEpIHtcbiAgICAgICAgLy8gcHJpbnQgdGhlIHRhc2sgQVJOXG4gICAgICAgIGNvbnNvbGUubG9nKGBDb250YWluZXIgJHtjb250YWluZXIubmFtZX0gZm91bmQgd2l0aFxuICAgICAgICAgICAgICAgICB2dWxuZXJhYmxlIGltYWdlICR7ZXZlbnRJbWdEaWdlc3R9LiBSZWZlciB0byB0YXNrIEFSTiAke3Rhc2sudGFza0Fybn1gKTtcbiAgICAgICAgLy8gcHJpbnQgdGhlIGVudGlyZSBjb250YWluZXIgaW5mb3JtYXRpb25cbiAgICAgICAgY29uc29sZS5sb2coY29udGFpbmVyKTtcbiAgICAgIH1cbiAgICB9XG4gIH1cbn07XG5cbmV4cG9ydCBjb25zdCBoYW5kbGVyID0gYXN5bmMgZnVuY3Rpb24gKFxuICBldmVudDogRXZlbnRCcmlkZ2VFdmVudDxzdHJpbmcsIGFueT4sXG4gIGNvbnRleHQ6IENvbnRleHQsXG4gIGNhbGxiYWNrOiBDYWxsYmFja1xuKSB7XG4gIC8vIGNvbnNvbGUubG9nKGBcbiAgLy8gIyMjIyMjIyMjIyMjIyMjXG4gIC8vICR7SlNPTi5zdHJpbmdpZnkoZXZlbnQpfVxuICAvLyAjIyMjIyMjIyMjIyMjIyNcbiAgLy8gYClcbiAgY29uc3QgZXZlbnRJbWFnZUFSTjogc3RyaW5nID0gZXZlbnQucmVzb3VyY2VzWzBdO1xuICAvLyBjb25zdCBldmVudEltYWdlRGlnZXN0OiBzdHJpbmcgPSBldmVudC5kZXRhaWwucmVzb3VyY2VzLmF3c0VjckNvbnRhaW5lckltYWdlLmltYWdlSGFzaFxuICBjb25zdCBldmVudEltYWdlQVJORGlnZXN0SW5kZXggPSBldmVudEltYWdlQVJOLmxhc3RJbmRleE9mKFwiL3NoYTI1NjpcIik7XG4gIGNvbnN0IGV2ZW50SW1hZ2VEaWdlc3QgPSBldmVudEltYWdlQVJOLnNsaWNlKGV2ZW50SW1hZ2VBUk5EaWdlc3RJbmRleCArIDEpOyAvLyBhZGRlZCArIDEgdG8gcmVtb3ZlIHRoZSAvIGluIHRoZSBzdHJpbmdcbiAgLy8gY29uc29sZS5sb2coYFxuICAvLyAjIyMjIyMjIyMjIyMjIyNcbiAgLy8gVGhpcyBpcyB0aGUgZXZlbnQgaW1hZ2UgZGlnZXN0OiAke2V2ZW50SW1hZ2VEaWdlc3R9XG4gIC8vICMjIyMjIyMjIyMjIyMjI1xuICAvLyBgKTtcblxuICBjb25zdCBjbHVzdGVyTGlzdCA9IGF3YWl0IGdldExpc3RPZkNsdXN0ZXJBUk4oKTtcbiAgZm9yIChjb25zdCBjbHVzdGVyIG9mIGNsdXN0ZXJMaXN0KSB7XG4gICAgY29uc3QgdnVsblJlc291cmNlcyA9IGF3YWl0IGdldFZ1bG5lcmFibGVUYXNrTGlzdChcbiAgICAgIGV2ZW50SW1hZ2VEaWdlc3QsXG4gICAgICBjbHVzdGVyXG4gICAgKTtcbiAgICBwcmludExvZ01lc3NhZ2UodnVsblJlc291cmNlcywgZXZlbnRJbWFnZURpZ2VzdCk7XG4gIH1cbn07XG4iXX0=