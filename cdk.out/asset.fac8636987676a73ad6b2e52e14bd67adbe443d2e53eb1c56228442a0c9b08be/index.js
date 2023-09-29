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
        console.log(`
      #############
      list tasks from cluster arn: ${response.taskArns} 
      #############
      `);
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
        clusters: [clusterARN]
    };
    const command = new client_ecs_1.DescribeClustersCommand(input);
    const response = await ecs.send(command);
    if (response != undefined) {
        return response.clusters[0].clusterName;
    }
    return undefined;
};
// filters list of tasks to just vulnerable tasks
const getVulnerableTaskList = async (eventImageDigest, clusterARN) => {
    const vulnerableTaskList = [];
    const clusterName = await getClusterName(clusterARN);
    const taskList = await listTasksFromClusterARN(clusterARN);
    if (taskList === undefined) {
        console.log(`No ECS tasks found in cluster ${clusterName}`);
    }
    else {
        for (const task of taskList) {
            if (formatTaskName(task) === eventImageDigest) {
                vulnerableTaskList.push(task);
            }
        }
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
    if (listOfVulnerableTasks == undefined || listOfVulnerableTasks.length === 0) {
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
            tasks: listOfVulnerableTasks
        };
        const command = new client_ecs_1.DescribeTasksCommand(input);
        const response = await ecs.send(command);
        for (const task of response.tasks) {
            for (const container of task.containers) {
                console.log(`Container ${container.name} found with
                 vulnerable image. Refer to task ARN ${task.taskArn}`);
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyJpbmRleC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFDQSxvREFNNkI7QUFFN0IsTUFBTSxHQUFHLEdBQUcsSUFBSSxzQkFBUyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0FBRTlCLE1BQU0sbUJBQW1CLEdBQUcsS0FBSyxJQUF1QixFQUFFO0lBRXhELElBQUksV0FBVyxHQUFhLEVBQUUsQ0FBQztJQUMvQixJQUFJLFNBQTZCLENBQUM7SUFFbEMsTUFBTSxLQUFLLEdBQUcsRUFBRSxDQUFDO0lBQ2pCLE1BQU0sT0FBTyxHQUFHLElBQUksZ0NBQW1CLENBQUMsS0FBSyxDQUFDLENBQUM7SUFDL0MsR0FBRztRQUNELE1BQU0sUUFBUSxHQUFHLE1BQU0sR0FBRyxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsQ0FBQztRQUN6QyxnQkFBZ0I7UUFDaEIsb0JBQW9CO1FBQ3BCLHFEQUFxRDtRQUNyRCxvQkFBb0I7UUFDcEIsS0FBSztRQUNMLElBQUksUUFBUSxJQUFJLFNBQVMsRUFBRTtZQUN6QixnQ0FBZ0M7WUFDaEMsc0JBQXNCO1lBQ3RCLFNBQVMsR0FBRyxRQUFRLENBQUMsU0FBUyxDQUFDO1lBQy9CLFdBQVcsR0FBRyxXQUFXLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxXQUFZLENBQUMsQ0FBQztTQUN6RDtLQUNGLFFBQVEsU0FBUyxFQUFFO0lBQ3BCLE9BQU8sV0FBVyxDQUFDO0FBQ3JCLENBQUMsQ0FBQztBQUNGLHNEQUFzRDtBQUN0RCxNQUFNLHVCQUF1QixHQUFHLEtBQUssRUFBRSxXQUFtQixFQUFFLEVBQUU7SUFFNUQsSUFBSSxRQUFRLEdBQWEsRUFBRSxDQUFDO0lBQzVCLElBQUksU0FBOEIsQ0FBQztJQUVuQyxHQUFHO1FBQ0QsTUFBTSxLQUFLLEdBQUc7WUFDWixPQUFPLEVBQUUsV0FBVztTQUNyQixDQUFDO1FBQ0YsTUFBTSxPQUFPLEdBQUcsSUFBSSw2QkFBZ0IsQ0FBQyxL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LHdCQUF3QixHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUMsMENBQTBDO0lBQ3RILGdCQUFnQjtJQUNoQixrQkFBa0I7SUFDbEIsc0RBQXNEO0lBQ3RELGtCQUFrQjtJQUNsQixNQUFNO0lBRU4sTUFBTSxXQUFXLEdBQUcsTUFBTSxtQkFBbUIsRUFBRSxDQUFDO0lBQ2hELEtBQUssTUFBTSxPQUFPLElBQUksV0FBVyxFQUFFO1FBQ2pDLE1BQU0sYUFBYSxHQUFHLE1BQU0scUJBQXFCLENBQUMsZ0JBQWdCLEVBQUMsT0FBTyxDQUFDLENBQUM7UUFDNUUsZUFBZSxDQUFDLGFBQWEsRUFBRSxnQkFBZ0IsQ0FBQyxDQUFDO0tBQ2xEO0FBQ0gsQ0FBQyxDQUFBO0FBekJZLFFBQUEsT0FBTyxXQXlCbkIiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBDYWxsYmFjaywgRXZlbnRCcmlkZ2VFdmVudCwgQ29udGV4dCB9IGZyb20gXCJhd3MtbGFtYmRhXCI7XG5pbXBvcnQge1xuICBFQ1NDbGllbnQsXG4gIExpc3RDbHVzdGVyc0NvbW1hbmQsXG4gIExpc3RUYXNrc0NvbW1hbmQsXG4gIERlc2NyaWJlVGFza3NDb21tYW5kLFxuICBEZXNjcmliZUNsdXN0ZXJzQ29tbWFuZFxufSBmcm9tIFwiQGF3cy1zZGsvY2xpZW50LWVjc1wiO1xuXG5jb25zdCBlY3MgPSBuZXcgRUNTQ2xpZW50KHt9KTtcblxuY29uc3QgZ2V0TGlzdE9mQ2x1c3RlckFSTiA9IGFzeW5jICgpOiBQcm9taXNlPHN0cmluZ1tdPiA9PiB7XG5cbiAgbGV0IGNsdXN0ZXJMaXN0OiBzdHJpbmdbXSA9IFtdO1xuICBsZXQgbmV4dFRva2VuOiBzdHJpbmcgfCB1bmRlZmluZWQ7IFxuXG4gIGNvbnN0IGlucHV0ID0ge307XG4gIGNvbnN0IGNvbW1hbmQgPSBuZXcgTGlzdENsdXN0ZXJzQ29tbWFuZChpbnB1dCk7XG4gIGRvIHtcbiAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGVjcy5zZW5kKGNvbW1hbmQpO1xuICAgIC8vIGNvbnNvbGUubG9nKGBcbiAgICAvLyAgICAgIyMjIyMjIyMjIyMjI1xuICAgIC8vICAgICBsaXN0IG9mIGNsdXN0ZXJzOiAgJHtKU09OLnN0cmluZ2lmeShyZXNwb25zZSl9XG4gICAgLy8gICAgICMjIyMjIyMjIyMjIyNcbiAgICAvLyBgKVxuICAgIGlmIChyZXNwb25zZSAhPSB1bmRlZmluZWQpIHtcbiAgICAgIC8vIHJldHVybiByZXNwb25zZS5jbHVzdGVyQXJucyE7XG4gICAgICAvLyBzZXQgbmV4dCB0b2tlbiBoZXJlXG4gICAgICBuZXh0VG9rZW4gPSByZXNwb25zZS5uZXh0VG9rZW47XG4gICAgICBjbHVzdGVyTGlzdCA9IGNsdXN0ZXJMaXN0LmNvbmNhdChyZXNwb25zZS5jbHVzdGVyQXJucyEpO1xuICAgIH1cbiAgfSAgd2hpbGUobmV4dFRva2VuKTtcbiAgcmV0dXJuIGNsdXN0ZXJMaXN0O1xufTtcbi8vIHJldHVybnMgbGlzdCBvZiBBTEwgdGFzayBBUk4gZnJvbSBzcGVjaWZpZWQgY2x1c3RlclxuY29uc3QgbGlzdFRhc2tzRnJvbUNsdXN0ZXJBUk4gPSBhc3luYyAoY2x1c3Rlck5hbWU6IHN0cmluZykgPT4ge1xuXG4gIGxldCB0YXNrTGlzdDogc3RyaW5nW10gPSBbXTtcbiAgbGV0IG5leHRUb2tlbjogIHN0cmluZyB8IHVuZGVmaW5lZDsgXG5cbiAgZG8ge1xuICAgIGNvbnN0IGlucHV0ID0ge1xuICAgICAgY2x1c3RlcjogY2x1c3Rlck5hbWUsXG4gICAgfTtcbiAgICBjb25zdCBjb21tYW5kID0gbmV3IExpc3RUYXNrc0NvbW1hbmQoaW5wdXQpO1xuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4gICAgY29uc29sZS5sb2coYFxuICAgICAgIyMjIyMjIyMjIyMjI1xuICAgICAgbGlzdCB0YXNrcyBmcm9tIGNsdXN0ZXIgYXJuOiAke3Jlc3BvbnNlLnRhc2tBcm5zfSBcbiAgICAgICMjIyMjIyMjIyMjIyNcbiAgICAgIGApO1xuICAgIC8vIHJldHVybiByZXNwb25zZS50YXNrQXJucztcbiAgICBpZiAocmVzcG9uc2UgIT0gdW5kZWZpbmVkKSB7XG4gICAgICBuZXh0VG9rZW4gPSByZXNwb25zZS5uZXh0VG9rZW47XG4gICAgICB0YXNrTGlzdCA9IHRhc2tMaXN0LmNvbmNhdChyZXNwb25zZS50YXNrQXJucyEpO1xuICAgIH1cbiAgfSB3aGlsZSAobmV4dFRva2VuKTtcbiAgcmV0dXJuIHRhc2tMaXN0O1xufTsgXG5cbi8vIGZvcm1hdHMgdGFzayBBUk4gdG8gSURcbmNvbnN0IGZvcm1hdFRhc2tOYW1lID0gKHRhc2tBUk46IHN0cmluZyk6IHN0cmluZyA9PiB7XG4gIGNvbnN0IGluZGV4T2ZMYXN0U2xhc2ggPSB0YXNrQVJOLmxhc3RJbmRleE9mKFwiL1wiKTtcbiAgY29uc3QgdGFza05hbWUgPSB0YXNrQVJOLnN1YnN0cmluZyhpbmRleE9mTGFzdFNsYXNoICsgMSk7XG4gIHJldHVybiB0YXNrTmFtZTtcbn07XG5cbmNvbnN0IGdldFZ1bG5lcmFibGVEaWdlc3RzUGVyQVJOID0gYXN5bmMgKGNsdXN0ZXJBUk46IHN0cmluZyk6IFByb21pc2U8YW55PiA9PiB7XG4gIGNvbnN0IHRhc2tMaXN0ID0gYXdhaXQgbGlzdFRhc2tzRnJvbUNsdXN0ZXJBUk4oY2x1c3RlckFSTik7XG4gIGxldCB2dWxuZXJhYmxlRGlnZXN0czogeyBba2V5OiBzdHJpbmddOiBzdHJpbmdbXSB9ID0ge307XG4gIGlmICh0YXNrTGlzdCAhPSB1bmRlZmluZWQpIHtcbiAgICBjb25zdCB0YXNrSWRMaXN0ID0gdGFza0xpc3QubWFwKCh0YXNrOiBzdHJpbmcpID0+IGZvcm1hdFRhc2tOYW1lKHRhc2spKTtcbiAgICBjb25zdCBpbnB1dCA9IHtcbiAgICAgIHRhc2tzOiB0YXNrSWRMaXN0LFxuICAgICAgY2x1c3RlcjogY2x1c3RlckFSTixcbiAgICB9O1xuICAgIGNvbnN0IGNvbW1hbmQgPSBuZXcgRGVzY3JpYmVUYXNrc0NvbW1hbmQoaW5wdXQpO1xuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4gICAgY29uc3QgbGlzdE9mVGFza3NGcm9tUmVzcG9uc2UgPSByZXNwb25zZS50YXNrcztcbiAgICBpZiAobGlzdE9mVGFza3NGcm9tUmVzcG9uc2UgIT0gdW5kZWZpbmVkKSB7XG4gICAgICBmb3IgKGNvbnN0IHRhc2sgb2YgbGlzdE9mVGFza3NGcm9tUmVzcG9uc2UpIHtcbiAgICAgICAgZm9yIChsZXQgbiA9IDA7IG4gPCB0YXNrLmNvbnRhaW5lcnMhLmxlbmd0aDsgbisrKSB7XG4gICAgICAgICAgaWYgKHRhc2suY29udGFpbmVycyFbbl0udGFza0FybiEgaW4gdnVsbmVyYWJsZURpZ2VzdHMpIHtcbiAgICAgICAgICAgIHZ1bG5lcmFibGVEaWdlc3RzW3Rhc2suY29udGFpbmVycyFbbl0udGFza0FybiFdLnB1c2goXG4gICAgICAgICAgICAgIHRhc2suY29udGFpbmVycyFbbl0uaW1hZ2VEaWdlc3QhXG4gICAgICAgICAgICApO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB2dWxuZXJhYmxlRGlnZXN0c1t0YXNrLmNvbnRhaW5lcnMhW25dLnRhc2tBcm4hXSA9IFtcbiAgICAgICAgICAgICAgdGFzay5jb250YWluZXJzIVtuXS5pbWFnZURpZ2VzdCEsXG4gICAgICAgICAgICBdO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gdnVsbmVyYWJsZURpZ2VzdHM7XG4gIH1cbiAgcmV0dXJuIHVuZGVmaW5lZDtcbn07XG5cbi8vIHJldHVybnMgdGhlIG5hbWUgb2YgdGhlIGNsdXN0ZXIgb3IgdW5kZWZpbmVkIGlmIG5vdCBmb3VuZFxuY29uc3QgZ2V0Q2x1c3Rlck5hbWUgPSBhc3luYyAoY2x1c3RlckFSTjogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmcgfCB1bmRlZmluZWQ+ID0+IHtcbiAgICBjb25zdCBpbnB1dCA9IHtcbiAgICAgICAgY2x1c3RlcnM6IFtjbHVzdGVyQVJOXVxuICAgIH1cbiAgICBjb25zdCBjb21tYW5kID0gbmV3IERlc2NyaWJlQ2x1c3RlcnNDb21tYW5kKGlucHV0KTtcbiAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGVjcy5zZW5kKGNvbW1hbmQpO1xuICAgIGlmIChyZXNwb25zZSAhPSB1bmRlZmluZWQpIHtcbiAgICAgICAgcmV0dXJuIHJlc3BvbnNlLmNsdXN0ZXJzIVswXS5jbHVzdGVyTmFtZSFcbiAgICB9XG4gICAgcmV0dXJuIHVuZGVmaW5lZFxufSBcblxuLy8gZmlsdGVycyBsaXN0IG9mIHRhc2tzIHRvIGp1c3QgdnVsbmVyYWJsZSB0YXNrc1xuY29uc3QgZ2V0VnVsbmVyYWJsZVRhc2tMaXN0ID0gYXN5bmMgKGV2ZW50SW1hZ2VEaWdlc3Q6IHN0cmluZywgY2x1c3RlckFSTjogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmdbXSB8IHVuZGVmaW5lZD4gPT4ge1xuICBjb25zdCB2dWxuZXJhYmxlVGFza0xpc3Q6IHN0cmluZ1tdID0gW107XG4gIGNvbnN0IGNsdXN0ZXJOYW1lID0gYXdhaXQgZ2V0Q2x1c3Rlck5hbWUoY2x1c3RlckFSTik7XG4gIGNvbnN0IHRhc2tMaXN0ID0gYXdhaXQgbGlzdFRhc2tzRnJvbUNsdXN0ZXJBUk4oY2x1c3RlckFSTik7XG4gICAgaWYgKHRhc2tMaXN0ID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgY29uc29sZS5sb2coYE5vIEVDUyB0YXNrcyBmb3VuZCBpbiBjbHVzdGVyICR7Y2x1c3Rlck5hbWV9YCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIGZvciAoY29uc3QgdGFzayBvZiB0YXNrTGlzdCkge1xuICAgICAgICAgIGlmIChmb3JtYXRUYXNrTmFtZSh0YXNrKSA9PT0gZXZlbnRJbWFnZURpZ2VzdCkge1xuICAgICAgICAgICAgdnVsbmVyYWJsZVRhc2tMaXN0LnB1c2godGFzayk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICByZXR1cm4gdnVsbmVyYWJsZVRhc2tMaXN0O1xuICB9XG4gIHJldHVybiB1bmRlZmluZWQ7XG59OyBcblxuXG5jb25zdCBjb21wYXJlRGlnZXN0cyA9IChcbiAgZXZlbnRJbWFnZURpZ2VzdDogc3RyaW5nLFxuICBpbWFnZURpZ2VzdDogc3RyaW5nXG4pOiBib29sZWFuID0+IHtcbiAgcmV0dXJuIGV2ZW50SW1hZ2VEaWdlc3QgPT09IGltYWdlRGlnZXN0O1xufTtcblxuLy8gdGFrZXMgbGlzdCBvZiB2dWxuZXJhYmxlIHRhc2sgQVJOIGFuZCBldmVudGltYWdlZGlnZXN0XG4vLyBwcmludHMgdGhlIGNvbnRhaW5lciBuYW1lIGFsb25nIHdpdGggdGhlIHRhc2sgQVJOIFxuY29uc3QgcHJpbnRMb2dNZXNzYWdlID0gYXN5bmMgKGxpc3RPZlZ1bG5lcmFibGVUYXNrczogc3RyaW5nW10gfCB1bmRlZmluZWQsIGV2ZW50SW1nRGlnZXN0OiBzdHJpbmcpID0+IHtcbiAgaWYgKGxpc3RPZlZ1bG5lcmFibGVUYXNrcyA9PSB1bmRlZmluZWQgfHwgbGlzdE9mVnVsbmVyYWJsZVRhc2tzLmxlbmd0aCA9PT0gMCkge1xuICAgIGNvbnNvbGUubG9nKGBObyBFQ1MgdGFza3Mgd2l0aCB2dWxuZXJhYmxlIGltYWdlICR7ZXZlbnRJbWdEaWdlc3R9IGZvdW5kLmApO1xuICB9IGVsc2Uge1xuICAgIC8vIGZvciAoY29uc3QgdnVsbkRpZ2VzdCBvZiBsaXN0T2ZWdWxuZXJhYmxlVGFza3MpIHtcbiAgICAvLyAgIGlmIChjb21wYXJlRGlnZXN0cyh2dWxuRGlnZXN0LCBldmVudEltZ0RpZ2VzdCkpIHtcbiAgICAvLyAgICAgY29uc29sZS5sb2coXG4gICAgLy8gICAgICAgYEVDUyB0YXNrIHdpdGggdnVsbmVyYWJsZSBpbWFnZSAke2V2ZW50SW1nRGlnZXN0fSBmb3VuZDogJHt2dWxuRGlnZXN0fWBcbiAgICAvLyAgICAgKTtcbiAgICAvLyAgICAgY29uc29sZS5sb2coYCR7dnVsbkRpZ2VzdH1gKTtcbiAgICAvLyAgICAgLy8gcHJpbnQgdGhlIGVudGlyZSB0YXNrIGRlc2NyaXB0aW9uXG4gICAgLy8gICB9XG4gICAgLy8gfVxuICAgIGNvbnN0IGlucHV0ID0ge1xuICAgICAgICB0YXNrczogbGlzdE9mVnVsbmVyYWJsZVRhc2tzXG4gICAgfVxuICAgIGNvbnN0IGNvbW1hbmQgPSBuZXcgRGVzY3JpYmVUYXNrc0NvbW1hbmQoaW5wdXQpO1xuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4gICAgZm9yIChjb25zdCB0YXNrIG9mIHJlc3BvbnNlLnRhc2tzISkge1xuICAgICAgICBmb3IgKGNvbnN0IGNvbnRhaW5lciBvZiB0YXNrLmNvbnRhaW5lcnMhKSB7XG4gICAgICAgICAgICAgICAgY29uc29sZS5sb2coYENvbnRhaW5lciAke2NvbnRhaW5lci5uYW1lfSBmb3VuZCB3aXRoXG4gICAgICAgICAgICAgICAgIHZ1bG5lcmFibGUgaW1hZ2UuIFJlZmVyIHRvIHRhc2sgQVJOICR7dGFzay50YXNrQXJufWApXG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9ICAgIFxufTtcblxuZXhwb3J0IGNvbnN0IGhhbmRsZXIgPSBhc3luYyBmdW5jdGlvbiAoXG4gIGV2ZW50OiBFdmVudEJyaWRnZUV2ZW50PHN0cmluZywgYW55PixcbiAgY29udGV4dDogQ29udGV4dCxcbiAgY2FsbGJhY2s6IENhbGxiYWNrXG4pIHtcbiAgLy8gY29uc29sZS5sb2coYFxuICAvLyAjIyMjIyMjIyMjIyMjIyNcbiAgLy8gJHtKU09OLnN0cmluZ2lmeShldmVudCl9XG4gIC8vICMjIyMjIyMjIyMjIyMjI1xuICAvLyBgKVxuICBjb25zdCBldmVudEltYWdlQVJOOiBzdHJpbmcgPSBldmVudC5yZXNvdXJjZXNbMF07XG4gIC8vIGNvbnN0IGV2ZW50SW1hZ2VEaWdlc3Q6IHN0cmluZyA9IGV2ZW50LmRldGFpbC5yZXNvdXJjZXMuYXdzRWNyQ29udGFpbmVySW1hZ2UuaW1hZ2VIYXNoXG4gIGNvbnN0IGV2ZW50SW1hZ2VBUk5EaWdlc3RJbmRleCA9IGV2ZW50SW1hZ2VBUk4ubGFzdEluZGV4T2YoXCIvc2hhMjU2OlwiKTtcbiAgY29uc3QgZXZlbnRJbWFnZURpZ2VzdCA9IGV2ZW50SW1hZ2VBUk4uc2xpY2UoZXZlbnRJbWFnZUFSTkRpZ2VzdEluZGV4ICsgMSk7IC8vIGFkZGVkICsgMSB0byByZW1vdmUgdGhlIC8gaW4gdGhlIHN0cmluZ1xuICAvLyBjb25zb2xlLmxvZyhgXG4gIC8vICMjIyMjIyMjIyMjIyMjI1xuICAvLyBUaGlzIGlzIHRoZSBldmVudCBpbWFnZSBkaWdlc3Q6ICR7ZXZlbnRJbWFnZURpZ2VzdH1cbiAgLy8gIyMjIyMjIyMjIyMjIyMjXG4gIC8vIGApO1xuXG4gIGNvbnN0IGNsdXN0ZXJMaXN0ID0gYXdhaXQgZ2V0TGlzdE9mQ2x1c3RlckFSTigpO1xuICBmb3IgKGNvbnN0IGNsdXN0ZXIgb2YgY2x1c3Rlckxpc3QpIHtcbiAgICBjb25zdCB2dWxuUmVzb3VyY2VzID0gYXdhaXQgZ2V0VnVsbmVyYWJsZVRhc2tMaXN0KGV2ZW50SW1hZ2VEaWdlc3QsY2x1c3Rlcik7XG4gICAgcHJpbnRMb2dNZXNzYWdlKHZ1bG5SZXNvdXJjZXMsIGV2ZW50SW1hZ2VEaWdlc3QpO1xuICB9XG59XG4iXX0=