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
    const formattedTasks = taskList.map((task) => formatTaskName(task));
    const input = {
        tasks: formattedTasks,
    };
    const command = new client_ecs_1.DescribeTasksCommand(input);
    const response = await ecs.send(command);
    console.log(response);
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyJpbmRleC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFDQSxvREFNNkI7QUFFN0IsTUFBTSxHQUFHLEdBQUcsSUFBSSxzQkFBUyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0FBRTlCLE1BQU0sbUJBQW1CLEdBQUcsS0FBSyxJQUF1QixFQUFFO0lBQ3hELElBQUksV0FBVyxHQUFhLEVBQUUsQ0FBQztJQUMvQixJQUFJLFNBQTZCLENBQUM7SUFFbEMsTUFBTSxLQUFLLEdBQUcsRUFBRSxDQUFDO0lBQ2pCLE1BQU0sT0FBTyxHQUFHLElBQUksZ0NBQW1CLENBQUMsS0FBSyxDQUFDLENBQUM7SUFDL0MsR0FBRztRQUNELE1BQU0sUUFBUSxHQUFHLE1BQU0sR0FBRyxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsQ0FBQztRQUN6QyxnQkFBZ0I7UUFDaEIsb0JBQW9CO1FBQ3BCLHFEQUFxRDtRQUNyRCxvQkFBb0I7UUFDcEIsS0FBSztRQUNMLElBQUksUUFBUSxJQUFJLFNBQVMsRUFBRTtZQUN6QixnQ0FBZ0M7WUFDaEMsc0JBQXNCO1lBQ3RCLFNBQVMsR0FBRyxRQUFRLENBQUMsU0FBUyxDQUFDO1lBQy9CLFdBQVcsR0FBRyxXQUFXLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxXQUFZLENBQUMsQ0FBQztTQUN6RDtLQUNGLFFBQVEsU0FBUyxFQUFFO0lBQ3BCLE9BQU8sV0FBVyxDQUFDO0FBQ3JCLENBQUMsQ0FBQztBQUNGLHNEQUFzRDtBQUN0RCxNQUFNLHVCQUF1QixHQUFHLEtBQUssRUFBRSxXQUFtQixFQUFFLEVBQUU7SUFDNUQsSUFBSSxRQUFRLEdBQWEsRUFBRSxDQUFDO0lBQzVCLElBQUksU0FBNkIsQ0FBQztJQUVsQyxHQUFHO1FBQ0QsTUFBTSxLQUFLLEdBQUc7WUFDWixPQUFPLEVBQUUsV0FBVztTQUNyQixDQUFDO1FBQ0YsTUFBTSxPQUFPLEdBQUcsSUFBSSw2QkFBZ0IsQ0FBQyxL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LE1BQU0sYUFBYSxHQUFHLE1BQU0scUJBQXFCLENBQy9DLGdCQUFnQixFQUNoQixPQUFPLENBQ1IsQ0FBQztRQUNGLGVBQWUsQ0FBQyxhQUFhLEVBQUUsZ0JBQWdCLENBQUMsQ0FBQztLQUNsRDtBQUNILENBQUMsQ0FBQztBQTVCVyxRQUFBLE9BQU8sV0E0QmxCIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgQ2FsbGJhY2ssIEV2ZW50QnJpZGdlRXZlbnQsIENvbnRleHQgfSBmcm9tIFwiYXdzLWxhbWJkYVwiO1xuaW1wb3J0IHtcbiAgRUNTQ2xpZW50LFxuICBMaXN0Q2x1c3RlcnNDb21tYW5kLFxuICBMaXN0VGFza3NDb21tYW5kLFxuICBEZXNjcmliZVRhc2tzQ29tbWFuZCxcbiAgRGVzY3JpYmVDbHVzdGVyc0NvbW1hbmQsXG59IGZyb20gXCJAYXdzLXNkay9jbGllbnQtZWNzXCI7XG5cbmNvbnN0IGVjcyA9IG5ldyBFQ1NDbGllbnQoe30pO1xuXG5jb25zdCBnZXRMaXN0T2ZDbHVzdGVyQVJOID0gYXN5bmMgKCk6IFByb21pc2U8c3RyaW5nW10+ID0+IHtcbiAgbGV0IGNsdXN0ZXJMaXN0OiBzdHJpbmdbXSA9IFtdO1xuICBsZXQgbmV4dFRva2VuOiBzdHJpbmcgfCB1bmRlZmluZWQ7XG5cbiAgY29uc3QgaW5wdXQgPSB7fTtcbiAgY29uc3QgY29tbWFuZCA9IG5ldyBMaXN0Q2x1c3RlcnNDb21tYW5kKGlucHV0KTtcbiAgZG8ge1xuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4gICAgLy8gY29uc29sZS5sb2coYFxuICAgIC8vICAgICAjIyMjIyMjIyMjIyMjXG4gICAgLy8gICAgIGxpc3Qgb2YgY2x1c3RlcnM6ICAke0pTT04uc3RyaW5naWZ5KHJlc3BvbnNlKX1cbiAgICAvLyAgICAgIyMjIyMjIyMjIyMjI1xuICAgIC8vIGApXG4gICAgaWYgKHJlc3BvbnNlICE9IHVuZGVmaW5lZCkge1xuICAgICAgLy8gcmV0dXJuIHJlc3BvbnNlLmNsdXN0ZXJBcm5zITtcbiAgICAgIC8vIHNldCBuZXh0IHRva2VuIGhlcmVcbiAgICAgIG5leHRUb2tlbiA9IHJlc3BvbnNlLm5leHRUb2tlbjtcbiAgICAgIGNsdXN0ZXJMaXN0ID0gY2x1c3Rlckxpc3QuY29uY2F0KHJlc3BvbnNlLmNsdXN0ZXJBcm5zISk7XG4gICAgfVxuICB9IHdoaWxlIChuZXh0VG9rZW4pO1xuICByZXR1cm4gY2x1c3Rlckxpc3Q7XG59O1xuLy8gcmV0dXJucyBsaXN0IG9mIEFMTCB0YXNrIEFSTiBmcm9tIHNwZWNpZmllZCBjbHVzdGVyXG5jb25zdCBsaXN0VGFza3NGcm9tQ2x1c3RlckFSTiA9IGFzeW5jIChjbHVzdGVyTmFtZTogc3RyaW5nKSA9PiB7XG4gIGxldCB0YXNrTGlzdDogc3RyaW5nW10gPSBbXTtcbiAgbGV0IG5leHRUb2tlbjogc3RyaW5nIHwgdW5kZWZpbmVkO1xuXG4gIGRvIHtcbiAgICBjb25zdCBpbnB1dCA9IHtcbiAgICAgIGNsdXN0ZXI6IGNsdXN0ZXJOYW1lLFxuICAgIH07XG4gICAgY29uc3QgY29tbWFuZCA9IG5ldyBMaXN0VGFza3NDb21tYW5kKGlucHV0KTtcbiAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGVjcy5zZW5kKGNvbW1hbmQpO1xuICAgIC8vIGNvbnNvbGUubG9nKGBcbiAgICAvLyAgICMjIyMjIyMjIyMjIyNcbiAgICAvLyAgIGxpc3QgdGFza3MgZnJvbSBjbHVzdGVyIGFybjogJHtyZXNwb25zZS50YXNrQXJuc31cbiAgICAvLyAgICMjIyMjIyMjIyMjIyNcbiAgICAvLyAgIGApO1xuICAgIC8vIHJldHVybiByZXNwb25zZS50YXNrQXJucztcbiAgICBpZiAocmVzcG9uc2UgIT0gdW5kZWZpbmVkKSB7XG4gICAgICBuZXh0VG9rZW4gPSByZXNwb25zZS5uZXh0VG9rZW47XG4gICAgICB0YXNrTGlzdCA9IHRhc2tMaXN0LmNvbmNhdChyZXNwb25zZS50YXNrQXJucyEpO1xuICAgIH1cbiAgfSB3aGlsZSAobmV4dFRva2VuKTtcbiAgcmV0dXJuIHRhc2tMaXN0O1xufTtcblxuLy8gZm9ybWF0cyB0YXNrIEFSTiB0byBJRFxuY29uc3QgZm9ybWF0VGFza05hbWUgPSAodGFza0FSTjogc3RyaW5nKTogc3RyaW5nID0+IHtcbiAgY29uc3QgaW5kZXhPZkxhc3RTbGFzaCA9IHRhc2tBUk4ubGFzdEluZGV4T2YoXCIvXCIpO1xuICBjb25zdCB0YXNrTmFtZSA9IHRhc2tBUk4uc3Vic3RyaW5nKGluZGV4T2ZMYXN0U2xhc2ggKyAxKTtcbiAgcmV0dXJuIHRhc2tOYW1lO1xufTtcblxuY29uc3QgZ2V0VnVsbmVyYWJsZURpZ2VzdHNQZXJBUk4gPSBhc3luYyAoY2x1c3RlckFSTjogc3RyaW5nKTogUHJvbWlzZTxhbnk+ID0+IHtcbiAgY29uc3QgdGFza0xpc3QgPSBhd2FpdCBsaXN0VGFza3NGcm9tQ2x1c3RlckFSTihjbHVzdGVyQVJOKTtcbiAgbGV0IHZ1bG5lcmFibGVEaWdlc3RzOiB7IFtrZXk6IHN0cmluZ106IHN0cmluZ1tdIH0gPSB7fTtcbiAgaWYgKHRhc2tMaXN0ICE9IHVuZGVmaW5lZCkge1xuICAgIGNvbnN0IHRhc2tJZExpc3QgPSB0YXNrTGlzdC5tYXAoKHRhc2s6IHN0cmluZykgPT4gZm9ybWF0VGFza05hbWUodGFzaykpO1xuICAgIGNvbnN0IGlucHV0ID0ge1xuICAgICAgdGFza3M6IHRhc2tJZExpc3QsXG4gICAgICBjbHVzdGVyOiBjbHVzdGVyQVJOLFxuICAgIH07XG4gICAgY29uc3QgY29tbWFuZCA9IG5ldyBEZXNjcmliZVRhc2tzQ29tbWFuZChpbnB1dCk7XG4gICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBlY3Muc2VuZChjb21tYW5kKTtcbiAgICBjb25zdCBsaXN0T2ZUYXNrc0Zyb21SZXNwb25zZSA9IHJlc3BvbnNlLnRhc2tzO1xuICAgIGlmIChsaXN0T2ZUYXNrc0Zyb21SZXNwb25zZSAhPSB1bmRlZmluZWQpIHtcbiAgICAgIGZvciAoY29uc3QgdGFzayBvZiBsaXN0T2ZUYXNrc0Zyb21SZXNwb25zZSkge1xuICAgICAgICBmb3IgKGxldCBuID0gMDsgbiA8IHRhc2suY29udGFpbmVycyEubGVuZ3RoOyBuKyspIHtcbiAgICAgICAgICBpZiAodGFzay5jb250YWluZXJzIVtuXS50YXNrQXJuISBpbiB2dWxuZXJhYmxlRGlnZXN0cykge1xuICAgICAgICAgICAgdnVsbmVyYWJsZURpZ2VzdHNbdGFzay5jb250YWluZXJzIVtuXS50YXNrQXJuIV0ucHVzaChcbiAgICAgICAgICAgICAgdGFzay5jb250YWluZXJzIVtuXS5pbWFnZURpZ2VzdCFcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHZ1bG5lcmFibGVEaWdlc3RzW3Rhc2suY29udGFpbmVycyFbbl0udGFza0FybiFdID0gW1xuICAgICAgICAgICAgICB0YXNrLmNvbnRhaW5lcnMhW25dLmltYWdlRGlnZXN0ISxcbiAgICAgICAgICAgIF07XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiB2dWxuZXJhYmxlRGlnZXN0cztcbiAgfVxuICByZXR1cm4gdW5kZWZpbmVkO1xufTtcblxuLy8gcmV0dXJucyB0aGUgbmFtZSBvZiB0aGUgY2x1c3RlciBvciB1bmRlZmluZWQgaWYgbm90IGZvdW5kXG5jb25zdCBnZXRDbHVzdGVyTmFtZSA9IGFzeW5jIChcbiAgY2x1c3RlckFSTjogc3RyaW5nXG4pOiBQcm9taXNlPHN0cmluZyB8IHVuZGVmaW5lZD4gPT4ge1xuICBjb25zdCBpbnB1dCA9IHtcbiAgICBjbHVzdGVyczogW2NsdXN0ZXJBUk5dLFxuICB9O1xuICBjb25zdCBjb21tYW5kID0gbmV3IERlc2NyaWJlQ2x1c3RlcnNDb21tYW5kKGlucHV0KTtcbiAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBlY3Muc2VuZChjb21tYW5kKTtcbiAgaWYgKHJlc3BvbnNlICE9IHVuZGVmaW5lZCkge1xuICAgIHJldHVybiByZXNwb25zZS5jbHVzdGVycyFbMF0uY2x1c3Rlck5hbWUhO1xuICB9XG4gIHJldHVybiB1bmRlZmluZWQ7XG59O1xuXG4vLyBmaWx0ZXJzIGxpc3Qgb2YgdGFza3MgdG8ganVzdCB2dWxuZXJhYmxlIHRhc2tzXG4vLyB0cnkgd2l0aCBqdXN0IHJldHVybmluZyBhIHRhc2tsaXN0XG5jb25zdCBnZXRWdWxuZXJhYmxlVGFza0xpc3QgPSBhc3luYyAoXG4gIGV2ZW50SW1hZ2VEaWdlc3Q6IHN0cmluZyxcbiAgY2x1c3RlckFSTjogc3RyaW5nXG4pOiBQcm9taXNlPHN0cmluZ1tdIHwgdW5kZWZpbmVkPiA9PiB7XG4gIGNvbnN0IHZ1bG5lcmFibGVUYXNrTGlzdDogc3RyaW5nW10gPSBbXTtcbiAgY29uc3QgY2x1c3Rlck5hbWUgPSBhd2FpdCBnZXRDbHVzdGVyTmFtZShjbHVzdGVyQVJOKTtcbiAgY29uc3QgdGFza0xpc3QgPSBhd2FpdCBsaXN0VGFza3NGcm9tQ2x1c3RlckFSTihjbHVzdGVyQVJOKTtcbiAgY29uc29sZS5sb2coYFRoZSBsaXN0IG9mIHRhc2tzOiAke3Rhc2tMaXN0Lm1hcCgodGFzayk9PmZvcm1hdFRhc2tOYW1lKHRhc2spKX1gKVxuICBjb25zdCBmb3JtYXR0ZWRUYXNrcyA9IHRhc2tMaXN0Lm1hcCgodGFzayk9PmZvcm1hdFRhc2tOYW1lKHRhc2spKTtcbiAgY29uc3QgaW5wdXQgPSB7XG4gICAgdGFza3M6IGZvcm1hdHRlZFRhc2tzLFxuICB9O1xuICBjb25zdCBjb21tYW5kID0gbmV3IERlc2NyaWJlVGFza3NDb21tYW5kKGlucHV0KTtcbiAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBlY3Muc2VuZChjb21tYW5kKTtcbiAgY29uc29sZS5sb2cocmVzcG9uc2UpO1xuICBpZiAodGFza0xpc3QgPT09IHVuZGVmaW5lZCkge1xuICAgIGNvbnNvbGUubG9nKGBObyBFQ1MgdGFza3MgZm91bmQgaW4gY2x1c3RlciAke2NsdXN0ZXJOYW1lfWApO1xuICB9IGVsc2Uge1xuICAgIGZvciAoY29uc3QgdGFzayBvZiB0YXNrTGlzdCkge1xuICAgICAgY29uc29sZS5sb2codGFzayk7XG4gICAgICBjb25zb2xlLmxvZyhmb3JtYXRUYXNrTmFtZSh0YXNrKSk7XG4gICAgICBpZiAoZm9ybWF0VGFza05hbWUodGFzaykgPT09IGV2ZW50SW1hZ2VEaWdlc3QpIHtcbiAgICAgICAgdnVsbmVyYWJsZVRhc2tMaXN0LnB1c2godGFzayk7XG4gICAgICB9XG4gICAgfVxuICAgIGNvbnNvbGUubG9nKHZ1bG5lcmFibGVUYXNrTGlzdCk7XG4gICAgcmV0dXJuIHZ1bG5lcmFibGVUYXNrTGlzdDtcbiAgfVxuICByZXR1cm4gdW5kZWZpbmVkO1xufTtcblxuY29uc3QgY29tcGFyZURpZ2VzdHMgPSAoXG4gIGV2ZW50SW1hZ2VEaWdlc3Q6IHN0cmluZyxcbiAgaW1hZ2VEaWdlc3Q6IHN0cmluZ1xuKTogYm9vbGVhbiA9PiB7XG4gIHJldHVybiBldmVudEltYWdlRGlnZXN0ID09PSBpbWFnZURpZ2VzdDtcbn07XG5cbi8vIHRha2VzIGxpc3Qgb2YgdnVsbmVyYWJsZSB0YXNrIEFSTiBhbmQgZXZlbnRpbWFnZWRpZ2VzdFxuLy8gcHJpbnRzIHRoZSBjb250YWluZXIgbmFtZSBhbG9uZyB3aXRoIHRoZSB0YXNrIEFSTlxuY29uc3QgcHJpbnRMb2dNZXNzYWdlID0gYXN5bmMgKFxuICBsaXN0T2ZWdWxuZXJhYmxlVGFza3M6IHN0cmluZ1tdIHwgdW5kZWZpbmVkLFxuICBldmVudEltZ0RpZ2VzdDogc3RyaW5nXG4pID0+IHtcbiAgaWYgKGxpc3RPZlZ1bG5lcmFibGVUYXNrcyA9PSB1bmRlZmluZWQpIHtcbiAgICBjb25zb2xlLmxvZyhcIlZ1bG5lcmFibGUgdGFzayBsaXN0IGlzIHVuZGVmaW5lZC5cIik7XG4gIH0gZWxzZSBpZiAobGlzdE9mVnVsbmVyYWJsZVRhc2tzLmxlbmd0aCA9PT0gMCkge1xuICAgIGNvbnNvbGUubG9nKGBObyBFQ1MgdGFza3Mgd2l0aCB2dWxuZXJhYmxlIGltYWdlICR7ZXZlbnRJbWdEaWdlc3R9IGZvdW5kLmApO1xuICB9IGVsc2Uge1xuICAgIC8vIGZvciAoY29uc3QgdnVsbkRpZ2VzdCBvZiBsaXN0T2ZWdWxuZXJhYmxlVGFza3MpIHtcbiAgICAvLyAgIGlmIChjb21wYXJlRGlnZXN0cyh2dWxuRGlnZXN0LCBldmVudEltZ0RpZ2VzdCkpIHtcbiAgICAvLyAgICAgY29uc29sZS5sb2coXG4gICAgLy8gICAgICAgYEVDUyB0YXNrIHdpdGggdnVsbmVyYWJsZSBpbWFnZSAke2V2ZW50SW1nRGlnZXN0fSBmb3VuZDogJHt2dWxuRGlnZXN0fWBcbiAgICAvLyAgICAgKTtcbiAgICAvLyAgICAgY29uc29sZS5sb2coYCR7dnVsbkRpZ2VzdH1gKTtcbiAgICAvLyAgICAgLy8gcHJpbnQgdGhlIGVudGlyZSB0YXNrIGRlc2NyaXB0aW9uXG4gICAgLy8gICB9XG4gICAgLy8gfVxuICAgIGNvbnN0IGlucHV0ID0ge1xuICAgICAgdGFza3M6IGxpc3RPZlZ1bG5lcmFibGVUYXNrcyxcbiAgICB9O1xuICAgIGNvbnN0IGNvbW1hbmQgPSBuZXcgRGVzY3JpYmVUYXNrc0NvbW1hbmQoaW5wdXQpO1xuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4gICAgZm9yIChjb25zdCB0YXNrIG9mIHJlc3BvbnNlLnRhc2tzISkge1xuICAgICAgZm9yIChjb25zdCBjb250YWluZXIgb2YgdGFzay5jb250YWluZXJzISkge1xuICAgICAgICAvLyBwcmludCB0aGUgdGFzayBBUk5cbiAgICAgICAgY29uc29sZS5sb2coYENvbnRhaW5lciAke2NvbnRhaW5lci5uYW1lfSBmb3VuZCB3aXRoXG4gICAgICAgICAgICAgICAgIHZ1bG5lcmFibGUgaW1hZ2UgJHtldmVudEltZ0RpZ2VzdH0uIFJlZmVyIHRvIHRhc2sgQVJOICR7dGFzay50YXNrQXJufWApO1xuICAgICAgICAvLyBwcmludCB0aGUgZW50aXJlIGNvbnRhaW5lciBpbmZvcm1hdGlvblxuICAgICAgICBjb25zb2xlLmxvZyhjb250YWluZXIpO1xuICAgICAgfVxuICAgIH1cbiAgfVxufTtcblxuZXhwb3J0IGNvbnN0IGhhbmRsZXIgPSBhc3luYyBmdW5jdGlvbiAoXG4gIGV2ZW50OiBFdmVudEJyaWRnZUV2ZW50PHN0cmluZywgYW55PixcbiAgY29udGV4dDogQ29udGV4dCxcbiAgY2FsbGJhY2s6IENhbGxiYWNrXG4pIHtcbiAgLy8gY29uc29sZS5sb2coYFxuICAvLyAjIyMjIyMjIyMjIyMjIyNcbiAgLy8gJHtKU09OLnN0cmluZ2lmeShldmVudCl9XG4gIC8vICMjIyMjIyMjIyMjIyMjI1xuICAvLyBgKVxuICBjb25zdCBldmVudEltYWdlQVJOOiBzdHJpbmcgPSBldmVudC5yZXNvdXJjZXNbMF07XG4gIC8vIGNvbnN0IGV2ZW50SW1hZ2VEaWdlc3Q6IHN0cmluZyA9IGV2ZW50LmRldGFpbC5yZXNvdXJjZXMuYXdzRWNyQ29udGFpbmVySW1hZ2UuaW1hZ2VIYXNoXG4gIGNvbnN0IGV2ZW50SW1hZ2VBUk5EaWdlc3RJbmRleCA9IGV2ZW50SW1hZ2VBUk4ubGFzdEluZGV4T2YoXCIvc2hhMjU2OlwiKTtcbiAgY29uc3QgZXZlbnRJbWFnZURpZ2VzdCA9IGV2ZW50SW1hZ2VBUk4uc2xpY2UoZXZlbnRJbWFnZUFSTkRpZ2VzdEluZGV4ICsgMSk7IC8vIGFkZGVkICsgMSB0byByZW1vdmUgdGhlIC8gaW4gdGhlIHN0cmluZ1xuICAvLyBjb25zb2xlLmxvZyhgXG4gIC8vICMjIyMjIyMjIyMjIyMjI1xuICAvLyBUaGlzIGlzIHRoZSBldmVudCBpbWFnZSBkaWdlc3Q6ICR7ZXZlbnRJbWFnZURpZ2VzdH1cbiAgLy8gIyMjIyMjIyMjIyMjIyMjXG4gIC8vIGApO1xuXG4gIGNvbnN0IGNsdXN0ZXJMaXN0ID0gYXdhaXQgZ2V0TGlzdE9mQ2x1c3RlckFSTigpO1xuICBmb3IgKGNvbnN0IGNsdXN0ZXIgb2YgY2x1c3Rlckxpc3QpIHtcbiAgICBjb25zdCB2dWxuUmVzb3VyY2VzID0gYXdhaXQgZ2V0VnVsbmVyYWJsZVRhc2tMaXN0KFxuICAgICAgZXZlbnRJbWFnZURpZ2VzdCxcbiAgICAgIGNsdXN0ZXJcbiAgICApO1xuICAgIHByaW50TG9nTWVzc2FnZSh2dWxuUmVzb3VyY2VzLCBldmVudEltYWdlRGlnZXN0KTtcbiAgfVxufTtcbiJdfQ==