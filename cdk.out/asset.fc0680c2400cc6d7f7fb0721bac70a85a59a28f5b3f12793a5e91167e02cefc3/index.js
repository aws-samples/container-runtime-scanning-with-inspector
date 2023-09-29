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
        console.log('Vulnerable task list is undefined.');
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
            tasks: listOfVulnerableTasks
        };
        const command = new client_ecs_1.DescribeTasksCommand(input);
        const response = await ecs.send(command);
        for (const task of response.tasks) {
            for (const container of task.containers) {
                if (compareDigests(container.imageDigest, eventImgDigest)) {
                    // print the task ARN
                    console.log(`Container ${container.name} found with
                 vulnerable image ${eventImgDigest}. Refer to task ARN ${task.taskArn}`);
                    // print the entire container information
                    console.log(container);
                }
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyJpbmRleC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFDQSxvREFNNkI7QUFFN0IsTUFBTSxHQUFHLEdBQUcsSUFBSSxzQkFBUyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0FBRTlCLE1BQU0sbUJBQW1CLEdBQUcsS0FBSyxJQUF1QixFQUFFO0lBRXhELElBQUksV0FBVyxHQUFhLEVBQUUsQ0FBQztJQUMvQixJQUFJLFNBQTZCLENBQUM7SUFFbEMsTUFBTSxLQUFLLEdBQUcsRUFBRSxDQUFDO0lBQ2pCLE1BQU0sT0FBTyxHQUFHLElBQUksZ0NBQW1CLENBQUMsS0FBSyxDQUFDLENBQUM7SUFDL0MsR0FBRztRQUNELE1BQU0sUUFBUSxHQUFHLE1BQU0sR0FBRyxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsQ0FBQztRQUN6QyxnQkFBZ0I7UUFDaEIsb0JBQW9CO1FBQ3BCLHFEQUFxRDtRQUNyRCxvQkFBb0I7UUFDcEIsS0FBSztRQUNMLElBQUksUUFBUSxJQUFJLFNBQVMsRUFBRTtZQUN6QixnQ0FBZ0M7WUFDaEMsc0JBQXNCO1lBQ3RCLFNBQVMsR0FBRyxRQUFRLENBQUMsU0FBUyxDQUFDO1lBQy9CLFdBQVcsR0FBRyxXQUFXLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxXQUFZLENBQUMsQ0FBQztTQUN6RDtLQUNGLFFBQVEsU0FBUyxFQUFFO0lBQ3BCLE9BQU8sV0FBVyxDQUFDO0FBQ3JCLENBQUMsQ0FBQztBQUNGLHNEQUFzRDtBQUN0RCxNQUFNLHVCQUF1QixHQUFHLEtBQUssRUFBRSxXQUFtQixFQUFFLEVBQUU7SUFFNUQsSUFBSSxRQUFRLEdBQWEsRUFBRSxDQUFDO0lBQzVCLElBQUksU0FBOEIsQ0FBQztJQUVuQyxHQUFHO1FBQ0QsTUFBTSxLQUFLLEdBQUc7WUFDWixPQUFPLEVBQUUsV0FBVztTQUNyQixDQUFDO1FBQ0YsTUFBTSxPQUFPLEdBQUcsSUFBSSw2QkFBZ0IsQ0FBQyxL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QixFQUNoQixRQUFrQjtJQUVsQixnQkFBZ0I7SUFDaEIsa0JBQWtCO0lBQ2xCLDJCQUEyQjtJQUMzQixrQkFBa0I7SUFDbEIsS0FBSztJQUNMLE1BQU0sYUFBYSxHQUFXLEtBQUssQ0FBQyxTQUFTLENBQUMsQ0FBQyxDQUFDLENBQUM7SUFDakQseUZBQXlGO0lBQ3pGLE1BQU0sd0JBQXdCLEdBQUcsYUFBYSxDQUFDLFdBQVcsQ0FBQyxVQUFVLENBQUMsQ0FBQztJQUN2RSxNQUFNLGdCQUFnQixHQUFHLGFBQWEsQ0FBQyxLQUFLLENBQUMsd0JBQXdCLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQywwQ0FBMEM7SUFDdEgsZ0JBQWdCO0lBQ2hCLGtCQUFrQjtJQUNsQixzREFBc0Q7SUFDdEQsa0JBQWtCO0lBQ2xCLE1BQU07SUFFTixNQUFNLFdBQVcsR0FBRyxNQUFNLG1CQUFtQixFQUFFLENBQUM7SUFDaEQsS0FBSyxNQUFNLE9BQU8sSUFBSSxXQUFXLEVBQUU7UUFDakMsTUFBTSxhQUFhLEdBQUcsTUFBTSxxQkFBcUIsQ0FBQyxnQkFBZ0IsRUFBQyxPQUFPLENBQUMsQ0FBQztRQUM1RSxlQUFlLENBQUMsYUFBYSxFQUFFLGdCQUFnQixDQUFDLENBQUM7S0FDbEQ7QUFDSCxDQUFDLENBQUE7QUF6QlksUUFBQSxPQUFPLFdBeUJuQiIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IENhbGxiYWNrLCBFdmVudEJyaWRnZUV2ZW50LCBDb250ZXh0IH0gZnJvbSBcImF3cy1sYW1iZGFcIjtcbmltcG9ydCB7XG4gIEVDU0NsaWVudCxcbiAgTGlzdENsdXN0ZXJzQ29tbWFuZCxcbiAgTGlzdFRhc2tzQ29tbWFuZCxcbiAgRGVzY3JpYmVUYXNrc0NvbW1hbmQsXG4gIERlc2NyaWJlQ2x1c3RlcnNDb21tYW5kXG59IGZyb20gXCJAYXdzLXNkay9jbGllbnQtZWNzXCI7XG5cbmNvbnN0IGVjcyA9IG5ldyBFQ1NDbGllbnQoe30pO1xuXG5jb25zdCBnZXRMaXN0T2ZDbHVzdGVyQVJOID0gYXN5bmMgKCk6IFByb21pc2U8c3RyaW5nW10+ID0+IHtcblxuICBsZXQgY2x1c3Rlckxpc3Q6IHN0cmluZ1tdID0gW107XG4gIGxldCBuZXh0VG9rZW46IHN0cmluZyB8IHVuZGVmaW5lZDsgXG5cbiAgY29uc3QgaW5wdXQgPSB7fTtcbiAgY29uc3QgY29tbWFuZCA9IG5ldyBMaXN0Q2x1c3RlcnNDb21tYW5kKGlucHV0KTtcbiAgZG8ge1xuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4gICAgLy8gY29uc29sZS5sb2coYFxuICAgIC8vICAgICAjIyMjIyMjIyMjIyMjXG4gICAgLy8gICAgIGxpc3Qgb2YgY2x1c3RlcnM6ICAke0pTT04uc3RyaW5naWZ5KHJlc3BvbnNlKX1cbiAgICAvLyAgICAgIyMjIyMjIyMjIyMjI1xuICAgIC8vIGApXG4gICAgaWYgKHJlc3BvbnNlICE9IHVuZGVmaW5lZCkge1xuICAgICAgLy8gcmV0dXJuIHJlc3BvbnNlLmNsdXN0ZXJBcm5zITtcbiAgICAgIC8vIHNldCBuZXh0IHRva2VuIGhlcmVcbiAgICAgIG5leHRUb2tlbiA9IHJlc3BvbnNlLm5leHRUb2tlbjtcbiAgICAgIGNsdXN0ZXJMaXN0ID0gY2x1c3Rlckxpc3QuY29uY2F0KHJlc3BvbnNlLmNsdXN0ZXJBcm5zISk7XG4gICAgfVxuICB9ICB3aGlsZShuZXh0VG9rZW4pO1xuICByZXR1cm4gY2x1c3Rlckxpc3Q7XG59O1xuLy8gcmV0dXJucyBsaXN0IG9mIEFMTCB0YXNrIEFSTiBmcm9tIHNwZWNpZmllZCBjbHVzdGVyXG5jb25zdCBsaXN0VGFza3NGcm9tQ2x1c3RlckFSTiA9IGFzeW5jIChjbHVzdGVyTmFtZTogc3RyaW5nKSA9PiB7XG5cbiAgbGV0IHRhc2tMaXN0OiBzdHJpbmdbXSA9IFtdO1xuICBsZXQgbmV4dFRva2VuOiAgc3RyaW5nIHwgdW5kZWZpbmVkOyBcblxuICBkbyB7XG4gICAgY29uc3QgaW5wdXQgPSB7XG4gICAgICBjbHVzdGVyOiBjbHVzdGVyTmFtZSxcbiAgICB9O1xuICAgIGNvbnN0IGNvbW1hbmQgPSBuZXcgTGlzdFRhc2tzQ29tbWFuZChpbnB1dCk7XG4gICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBlY3Muc2VuZChjb21tYW5kKTtcbiAgICAvLyBjb25zb2xlLmxvZyhgXG4gICAgLy8gICAjIyMjIyMjIyMjIyMjXG4gICAgLy8gICBsaXN0IHRhc2tzIGZyb20gY2x1c3RlciBhcm46ICR7cmVzcG9uc2UudGFza0FybnN9IFxuICAgIC8vICAgIyMjIyMjIyMjIyMjI1xuICAgIC8vICAgYCk7XG4gICAgLy8gcmV0dXJuIHJlc3BvbnNlLnRhc2tBcm5zO1xuICAgIGlmIChyZXNwb25zZSAhPSB1bmRlZmluZWQpIHtcbiAgICAgIG5leHRUb2tlbiA9IHJlc3BvbnNlLm5leHRUb2tlbjtcbiAgICAgIHRhc2tMaXN0ID0gdGFza0xpc3QuY29uY2F0KHJlc3BvbnNlLnRhc2tBcm5zISk7XG4gICAgfVxuICB9IHdoaWxlIChuZXh0VG9rZW4pO1xuICByZXR1cm4gdGFza0xpc3Q7XG59OyBcblxuLy8gZm9ybWF0cyB0YXNrIEFSTiB0byBJRFxuY29uc3QgZm9ybWF0VGFza05hbWUgPSAodGFza0FSTjogc3RyaW5nKTogc3RyaW5nID0+IHtcbiAgY29uc3QgaW5kZXhPZkxhc3RTbGFzaCA9IHRhc2tBUk4ubGFzdEluZGV4T2YoXCIvXCIpO1xuICBjb25zdCB0YXNrTmFtZSA9IHRhc2tBUk4uc3Vic3RyaW5nKGluZGV4T2ZMYXN0U2xhc2ggKyAxKTtcbiAgcmV0dXJuIHRhc2tOYW1lO1xufTtcblxuY29uc3QgZ2V0VnVsbmVyYWJsZURpZ2VzdHNQZXJBUk4gPSBhc3luYyAoY2x1c3RlckFSTjogc3RyaW5nKTogUHJvbWlzZTxhbnk+ID0+IHtcbiAgY29uc3QgdGFza0xpc3QgPSBhd2FpdCBsaXN0VGFza3NGcm9tQ2x1c3RlckFSTihjbHVzdGVyQVJOKTtcbiAgbGV0IHZ1bG5lcmFibGVEaWdlc3RzOiB7IFtrZXk6IHN0cmluZ106IHN0cmluZ1tdIH0gPSB7fTtcbiAgaWYgKHRhc2tMaXN0ICE9IHVuZGVmaW5lZCkge1xuICAgIGNvbnN0IHRhc2tJZExpc3QgPSB0YXNrTGlzdC5tYXAoKHRhc2s6IHN0cmluZykgPT4gZm9ybWF0VGFza05hbWUodGFzaykpO1xuICAgIGNvbnN0IGlucHV0ID0ge1xuICAgICAgdGFza3M6IHRhc2tJZExpc3QsXG4gICAgICBjbHVzdGVyOiBjbHVzdGVyQVJOLFxuICAgIH07XG4gICAgY29uc3QgY29tbWFuZCA9IG5ldyBEZXNjcmliZVRhc2tzQ29tbWFuZChpbnB1dCk7XG4gICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBlY3Muc2VuZChjb21tYW5kKTtcbiAgICBjb25zdCBsaXN0T2ZUYXNrc0Zyb21SZXNwb25zZSA9IHJlc3BvbnNlLnRhc2tzO1xuICAgIGlmIChsaXN0T2ZUYXNrc0Zyb21SZXNwb25zZSAhPSB1bmRlZmluZWQpIHtcbiAgICAgIGZvciAoY29uc3QgdGFzayBvZiBsaXN0T2ZUYXNrc0Zyb21SZXNwb25zZSkge1xuICAgICAgICBmb3IgKGxldCBuID0gMDsgbiA8IHRhc2suY29udGFpbmVycyEubGVuZ3RoOyBuKyspIHtcbiAgICAgICAgICBpZiAodGFzay5jb250YWluZXJzIVtuXS50YXNrQXJuISBpbiB2dWxuZXJhYmxlRGlnZXN0cykge1xuICAgICAgICAgICAgdnVsbmVyYWJsZURpZ2VzdHNbdGFzay5jb250YWluZXJzIVtuXS50YXNrQXJuIV0ucHVzaChcbiAgICAgICAgICAgICAgdGFzay5jb250YWluZXJzIVtuXS5pbWFnZURpZ2VzdCFcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHZ1bG5lcmFibGVEaWdlc3RzW3Rhc2suY29udGFpbmVycyFbbl0udGFza0FybiFdID0gW1xuICAgICAgICAgICAgICB0YXNrLmNvbnRhaW5lcnMhW25dLmltYWdlRGlnZXN0ISxcbiAgICAgICAgICAgIF07XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiB2dWxuZXJhYmxlRGlnZXN0cztcbiAgfVxuICByZXR1cm4gdW5kZWZpbmVkO1xufTtcblxuLy8gcmV0dXJucyB0aGUgbmFtZSBvZiB0aGUgY2x1c3RlciBvciB1bmRlZmluZWQgaWYgbm90IGZvdW5kXG5jb25zdCBnZXRDbHVzdGVyTmFtZSA9IGFzeW5jIChjbHVzdGVyQVJOOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZyB8IHVuZGVmaW5lZD4gPT4ge1xuICAgIGNvbnN0IGlucHV0ID0ge1xuICAgICAgICBjbHVzdGVyczogW2NsdXN0ZXJBUk5dXG4gICAgfVxuICAgIGNvbnN0IGNvbW1hbmQgPSBuZXcgRGVzY3JpYmVDbHVzdGVyc0NvbW1hbmQoaW5wdXQpO1xuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4gICAgaWYgKHJlc3BvbnNlICE9IHVuZGVmaW5lZCkge1xuICAgICAgICByZXR1cm4gcmVzcG9uc2UuY2x1c3RlcnMhWzBdLmNsdXN0ZXJOYW1lIVxuICAgIH1cbiAgICByZXR1cm4gdW5kZWZpbmVkXG59IFxuXG4vLyBmaWx0ZXJzIGxpc3Qgb2YgdGFza3MgdG8ganVzdCB2dWxuZXJhYmxlIHRhc2tzXG5jb25zdCBnZXRWdWxuZXJhYmxlVGFza0xpc3QgPSBhc3luYyAoZXZlbnRJbWFnZURpZ2VzdDogc3RyaW5nLCBjbHVzdGVyQVJOOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZ1tdIHwgdW5kZWZpbmVkPiA9PiB7XG4gIGNvbnN0IHZ1bG5lcmFibGVUYXNrTGlzdDogc3RyaW5nW10gPSBbXTtcbiAgY29uc3QgY2x1c3Rlck5hbWUgPSBhd2FpdCBnZXRDbHVzdGVyTmFtZShjbHVzdGVyQVJOKTtcbiAgY29uc3QgdGFza0xpc3QgPSBhd2FpdCBsaXN0VGFza3NGcm9tQ2x1c3RlckFSTihjbHVzdGVyQVJOKTtcbiAgICBpZiAodGFza0xpc3QgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICBjb25zb2xlLmxvZyhgTm8gRUNTIHRhc2tzIGZvdW5kIGluIGNsdXN0ZXIgJHtjbHVzdGVyTmFtZX1gKTtcbiAgICB9IGVsc2Uge1xuICAgICAgZm9yIChjb25zdCB0YXNrIG9mIHRhc2tMaXN0KSB7XG4gICAgICAgICAgaWYgKGZvcm1hdFRhc2tOYW1lKHRhc2spID09PSBldmVudEltYWdlRGlnZXN0KSB7XG4gICAgICAgICAgICB2dWxuZXJhYmxlVGFza0xpc3QucHVzaCh0YXNrKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgICAgY29uc29sZS5sb2codnVsbmVyYWJsZVRhc2tMaXN0KTtcbiAgICByZXR1cm4gdnVsbmVyYWJsZVRhc2tMaXN0O1xuICB9XG4gIHJldHVybiB1bmRlZmluZWQ7XG59OyBcblxuXG5jb25zdCBjb21wYXJlRGlnZXN0cyA9IChcbiAgZXZlbnRJbWFnZURpZ2VzdDogc3RyaW5nLFxuICBpbWFnZURpZ2VzdDogc3RyaW5nXG4pOiBib29sZWFuID0+IHtcbiAgcmV0dXJuIGV2ZW50SW1hZ2VEaWdlc3QgPT09IGltYWdlRGlnZXN0O1xufTtcblxuLy8gdGFrZXMgbGlzdCBvZiB2dWxuZXJhYmxlIHRhc2sgQVJOIGFuZCBldmVudGltYWdlZGlnZXN0XG4vLyBwcmludHMgdGhlIGNvbnRhaW5lciBuYW1lIGFsb25nIHdpdGggdGhlIHRhc2sgQVJOIFxuY29uc3QgcHJpbnRMb2dNZXNzYWdlID0gYXN5bmMgKGxpc3RPZlZ1bG5lcmFibGVUYXNrczogc3RyaW5nW10gfCB1bmRlZmluZWQsIGV2ZW50SW1nRGlnZXN0OiBzdHJpbmcpID0+IHtcbiAgaWYgKGxpc3RPZlZ1bG5lcmFibGVUYXNrcyA9PSB1bmRlZmluZWQpe1xuICAgIGNvbnNvbGUubG9nKCdWdWxuZXJhYmxlIHRhc2sgbGlzdCBpcyB1bmRlZmluZWQuJylcbiAgfSBlbHNlIGlmIChsaXN0T2ZWdWxuZXJhYmxlVGFza3MubGVuZ3RoID09PSAwKSB7XG4gICAgY29uc29sZS5sb2coYE5vIEVDUyB0YXNrcyB3aXRoIHZ1bG5lcmFibGUgaW1hZ2UgJHtldmVudEltZ0RpZ2VzdH0gZm91bmQuYCk7XG4gIH0gZWxzZSB7XG4gICAgLy8gZm9yIChjb25zdCB2dWxuRGlnZXN0IG9mIGxpc3RPZlZ1bG5lcmFibGVUYXNrcykge1xuICAgIC8vICAgaWYgKGNvbXBhcmVEaWdlc3RzKHZ1bG5EaWdlc3QsIGV2ZW50SW1nRGlnZXN0KSkge1xuICAgIC8vICAgICBjb25zb2xlLmxvZyhcbiAgICAvLyAgICAgICBgRUNTIHRhc2sgd2l0aCB2dWxuZXJhYmxlIGltYWdlICR7ZXZlbnRJbWdEaWdlc3R9IGZvdW5kOiAke3Z1bG5EaWdlc3R9YFxuICAgIC8vICAgICApO1xuICAgIC8vICAgICBjb25zb2xlLmxvZyhgJHt2dWxuRGlnZXN0fWApO1xuICAgIC8vICAgICAvLyBwcmludCB0aGUgZW50aXJlIHRhc2sgZGVzY3JpcHRpb25cbiAgICAvLyAgIH1cbiAgICAvLyB9XG4gICAgY29uc3QgaW5wdXQgPSB7XG4gICAgICAgIHRhc2tzOiBsaXN0T2ZWdWxuZXJhYmxlVGFza3NcbiAgICB9XG4gICAgY29uc3QgY29tbWFuZCA9IG5ldyBEZXNjcmliZVRhc2tzQ29tbWFuZChpbnB1dCk7XG4gICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBlY3Muc2VuZChjb21tYW5kKTtcbiAgICBmb3IgKGNvbnN0IHRhc2sgb2YgcmVzcG9uc2UudGFza3MhKSB7XG4gICAgICAgIGZvciAoY29uc3QgY29udGFpbmVyIG9mIHRhc2suY29udGFpbmVycyEpIHtcbiAgICAgICAgICAgIGlmIChjb21wYXJlRGlnZXN0cyhjb250YWluZXIuaW1hZ2VEaWdlc3QhLCBldmVudEltZ0RpZ2VzdCkpIHtcbiAgICAgICAgICAgICAgICAvLyBwcmludCB0aGUgdGFzayBBUk5cbiAgICAgICAgICAgICAgICBjb25zb2xlLmxvZyhgQ29udGFpbmVyICR7Y29udGFpbmVyLm5hbWV9IGZvdW5kIHdpdGhcbiAgICAgICAgICAgICAgICAgdnVsbmVyYWJsZSBpbWFnZSAke2V2ZW50SW1nRGlnZXN0fS4gUmVmZXIgdG8gdGFzayBBUk4gJHt0YXNrLnRhc2tBcm59YClcbiAgICAgICAgICAgICAgICAvLyBwcmludCB0aGUgZW50aXJlIGNvbnRhaW5lciBpbmZvcm1hdGlvblxuICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKGNvbnRhaW5lcik7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfSAgICBcbn07XG5cbmV4cG9ydCBjb25zdCBoYW5kbGVyID0gYXN5bmMgZnVuY3Rpb24gKFxuICBldmVudDogRXZlbnRCcmlkZ2VFdmVudDxzdHJpbmcsIGFueT4sXG4gIGNvbnRleHQ6IENvbnRleHQsXG4gIGNhbGxiYWNrOiBDYWxsYmFja1xuKSB7XG4gIC8vIGNvbnNvbGUubG9nKGBcbiAgLy8gIyMjIyMjIyMjIyMjIyMjXG4gIC8vICR7SlNPTi5zdHJpbmdpZnkoZXZlbnQpfVxuICAvLyAjIyMjIyMjIyMjIyMjIyNcbiAgLy8gYClcbiAgY29uc3QgZXZlbnRJbWFnZUFSTjogc3RyaW5nID0gZXZlbnQucmVzb3VyY2VzWzBdO1xuICAvLyBjb25zdCBldmVudEltYWdlRGlnZXN0OiBzdHJpbmcgPSBldmVudC5kZXRhaWwucmVzb3VyY2VzLmF3c0VjckNvbnRhaW5lckltYWdlLmltYWdlSGFzaFxuICBjb25zdCBldmVudEltYWdlQVJORGlnZXN0SW5kZXggPSBldmVudEltYWdlQVJOLmxhc3RJbmRleE9mKFwiL3NoYTI1NjpcIik7XG4gIGNvbnN0IGV2ZW50SW1hZ2VEaWdlc3QgPSBldmVudEltYWdlQVJOLnNsaWNlKGV2ZW50SW1hZ2VBUk5EaWdlc3RJbmRleCArIDEpOyAvLyBhZGRlZCArIDEgdG8gcmVtb3ZlIHRoZSAvIGluIHRoZSBzdHJpbmdcbiAgLy8gY29uc29sZS5sb2coYFxuICAvLyAjIyMjIyMjIyMjIyMjIyNcbiAgLy8gVGhpcyBpcyB0aGUgZXZlbnQgaW1hZ2UgZGlnZXN0OiAke2V2ZW50SW1hZ2VEaWdlc3R9XG4gIC8vICMjIyMjIyMjIyMjIyMjI1xuICAvLyBgKTtcblxuICBjb25zdCBjbHVzdGVyTGlzdCA9IGF3YWl0IGdldExpc3RPZkNsdXN0ZXJBUk4oKTtcbiAgZm9yIChjb25zdCBjbHVzdGVyIG9mIGNsdXN0ZXJMaXN0KSB7XG4gICAgY29uc3QgdnVsblJlc291cmNlcyA9IGF3YWl0IGdldFZ1bG5lcmFibGVUYXNrTGlzdChldmVudEltYWdlRGlnZXN0LGNsdXN0ZXIpO1xuICAgIHByaW50TG9nTWVzc2FnZSh2dWxuUmVzb3VyY2VzLCBldmVudEltYWdlRGlnZXN0KTtcbiAgfVxufVxuIl19