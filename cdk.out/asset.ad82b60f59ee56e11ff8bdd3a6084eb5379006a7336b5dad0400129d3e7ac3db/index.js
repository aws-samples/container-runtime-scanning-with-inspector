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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyJpbmRleC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFDQSxvREFNNkI7QUFFN0IsTUFBTSxHQUFHLEdBQUcsSUFBSSxzQkFBUyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0FBRTlCLE1BQU0sbUJBQW1CLEdBQUcsS0FBSyxJQUF1QixFQUFFO0lBRXhELElBQUksV0FBVyxHQUFhLEVBQUUsQ0FBQztJQUMvQixJQUFJLFNBQTZCLENBQUM7SUFFbEMsTUFBTSxLQUFLLEdBQUcsRUFBRSxDQUFDO0lBQ2pCLE1BQU0sT0FBTyxHQUFHLElBQUksZ0NBQW1CLENBQUMsS0FBSyxDQUFDLENBQUM7SUFDL0MsR0FBRztRQUNELE1BQU0sUUFBUSxHQUFHLE1BQU0sR0FBRyxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsQ0FBQztRQUN6QyxnQkFBZ0I7UUFDaEIsb0JBQW9CO1FBQ3BCLHFEQUFxRDtRQUNyRCxvQkFBb0I7UUFDcEIsS0FBSztRQUNMLElBQUksUUFBUSxJQUFJLFNBQVMsRUFBRTtZQUN6QixnQ0FBZ0M7WUFDaEMsc0JBQXNCO1lBQ3RCLFNBQVMsR0FBRyxRQUFRLENBQUMsU0FBUyxDQUFDO1lBQy9CLFdBQVcsR0FBRyxXQUFXLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxXQUFZLENBQUMsQ0FBQztTQUN6RDtLQUNGLFFBQVEsU0FBUyxFQUFFO0lBQ3BCLE9BQU8sV0FBVyxDQUFDO0FBQ3JCLENBQUMsQ0FBQztBQUNGLHNEQUFzRDtBQUN0RCxNQUFNLHVCQUF1QixHQUFHLEtBQUssRUFBRSxXQUFtQixFQUFFLEVBQUU7SUFFNUQsSUFBSSxRQUFRLEdBQWEsRUFBRSxDQUFDO0lBQzVCLElBQUksU0FBOEIsQ0FBQztJQUVuQyxHQUFHO1FBQ0QsTUFBTSxLQUFLLEdBQUc7WUFDWixPQUFPLEVBQUUsV0FBVztTQUNyQixDQUFDO1FBQ0YsTUFBTSxPQUFPLEdBQUcsSUFBSSw2QkFBZ0IsQ0FBQyxL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SUFDbEIsMkJBQTJCO0lBQzNCLGtCQUFrQjtJQUNsQixLQUFLO0lBQ0wsTUFBTSxhQUFhLEdBQVcsS0FBSyxDQUFDLFNBQVMsQ0FBQyxDQUFDLENBQUMsQ0FBQztJQUNqRCx5RkFBeUY7SUFDekYsTUFBTSx3QkFBd0IsR0FBRyxhQUFhLENBQUMsV0FBVyxDQUFDLFVBQVUsQ0FBQyxDQUFDO0lBQ3ZFLE1BQU0sZ0JBQWdCLEdBQUcsYUFBYSxDQUFDLEtBQUssQ0FBQyx3QkFBd0IsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFDLDBDQUEwQztJQUN0SCxnQkFBZ0I7SUFDaEIsa0JBQWtCO0lBQ2xCLHNEQUFzRDtJQUN0RCxrQkFBa0I7SUFDbEIsTUFBTTtJQUVOLE1BQU0sV0FBVyxHQUFHLE1BQU0sbUJBQW1CLEVBQUUsQ0FBQztJQUNoRCxLQUFLLE1BQU0sT0FBTyxJQUFJLFdBQVcsRUFBRTtRQUNqQyxNQUFNLGFBQWEsR0FBRyxNQUFNLHFCQUFxQixDQUFDLGdCQUFnQixFQUFDLE9BQU8sQ0FBQyxDQUFDO1FBQzVFLGVBQWUsQ0FBQyxhQUFhLEVBQUUsZ0JBQWdCLENBQUMsQ0FBQztLQUNsRDtBQUNILENBQUMsQ0FBQTtBQXpCWSxRQUFBLE9BQU8sV0F5Qm5CIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgQ2FsbGJhY2ssIEV2ZW50QnJpZGdlRXZlbnQsIENvbnRleHQgfSBmcm9tIFwiYXdzLWxhbWJkYVwiO1xuaW1wb3J0IHtcbiAgRUNTQ2xpZW50LFxuICBMaXN0Q2x1c3RlcnNDb21tYW5kLFxuICBMaXN0VGFza3NDb21tYW5kLFxuICBEZXNjcmliZVRhc2tzQ29tbWFuZCxcbiAgRGVzY3JpYmVDbHVzdGVyc0NvbW1hbmRcbn0gZnJvbSBcIkBhd3Mtc2RrL2NsaWVudC1lY3NcIjtcblxuY29uc3QgZWNzID0gbmV3IEVDU0NsaWVudCh7fSk7XG5cbmNvbnN0IGdldExpc3RPZkNsdXN0ZXJBUk4gPSBhc3luYyAoKTogUHJvbWlzZTxzdHJpbmdbXT4gPT4ge1xuXG4gIGxldCBjbHVzdGVyTGlzdDogc3RyaW5nW10gPSBbXTtcbiAgbGV0IG5leHRUb2tlbjogc3RyaW5nIHwgdW5kZWZpbmVkOyBcblxuICBjb25zdCBpbnB1dCA9IHt9O1xuICBjb25zdCBjb21tYW5kID0gbmV3IExpc3RDbHVzdGVyc0NvbW1hbmQoaW5wdXQpO1xuICBkbyB7XG4gICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBlY3Muc2VuZChjb21tYW5kKTtcbiAgICAvLyBjb25zb2xlLmxvZyhgXG4gICAgLy8gICAgICMjIyMjIyMjIyMjIyNcbiAgICAvLyAgICAgbGlzdCBvZiBjbHVzdGVyczogICR7SlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpfVxuICAgIC8vICAgICAjIyMjIyMjIyMjIyMjXG4gICAgLy8gYClcbiAgICBpZiAocmVzcG9uc2UgIT0gdW5kZWZpbmVkKSB7XG4gICAgICAvLyByZXR1cm4gcmVzcG9uc2UuY2x1c3RlckFybnMhO1xuICAgICAgLy8gc2V0IG5leHQgdG9rZW4gaGVyZVxuICAgICAgbmV4dFRva2VuID0gcmVzcG9uc2UubmV4dFRva2VuO1xuICAgICAgY2x1c3Rlckxpc3QgPSBjbHVzdGVyTGlzdC5jb25jYXQocmVzcG9uc2UuY2x1c3RlckFybnMhKTtcbiAgICB9XG4gIH0gIHdoaWxlKG5leHRUb2tlbik7XG4gIHJldHVybiBjbHVzdGVyTGlzdDtcbn07XG4vLyByZXR1cm5zIGxpc3Qgb2YgQUxMIHRhc2sgQVJOIGZyb20gc3BlY2lmaWVkIGNsdXN0ZXJcbmNvbnN0IGxpc3RUYXNrc0Zyb21DbHVzdGVyQVJOID0gYXN5bmMgKGNsdXN0ZXJOYW1lOiBzdHJpbmcpID0+IHtcblxuICBsZXQgdGFza0xpc3Q6IHN0cmluZ1tdID0gW107XG4gIGxldCBuZXh0VG9rZW46ICBzdHJpbmcgfCB1bmRlZmluZWQ7IFxuXG4gIGRvIHtcbiAgICBjb25zdCBpbnB1dCA9IHtcbiAgICAgIGNsdXN0ZXI6IGNsdXN0ZXJOYW1lLFxuICAgIH07XG4gICAgY29uc3QgY29tbWFuZCA9IG5ldyBMaXN0VGFza3NDb21tYW5kKGlucHV0KTtcbiAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGVjcy5zZW5kKGNvbW1hbmQpO1xuICAgIGNvbnNvbGUubG9nKGBcbiAgICAgICMjIyMjIyMjIyMjIyNcbiAgICAgIGxpc3QgdGFza3MgZnJvbSBjbHVzdGVyIGFybjogJHtyZXNwb25zZS50YXNrQXJuc30gXG4gICAgICAjIyMjIyMjIyMjIyMjXG4gICAgICBgKTtcbiAgICAvLyByZXR1cm4gcmVzcG9uc2UudGFza0FybnM7XG4gICAgaWYgKHJlc3BvbnNlICE9IHVuZGVmaW5lZCkge1xuICAgICAgbmV4dFRva2VuID0gcmVzcG9uc2UubmV4dFRva2VuO1xuICAgICAgdGFza0xpc3QgPSB0YXNrTGlzdC5jb25jYXQocmVzcG9uc2UudGFza0FybnMhKTtcbiAgICB9XG4gIH0gd2hpbGUgKG5leHRUb2tlbik7XG4gIHJldHVybiB0YXNrTGlzdDtcbn07IFxuXG4vLyBmb3JtYXRzIHRhc2sgQVJOIHRvIElEXG5jb25zdCBmb3JtYXRUYXNrTmFtZSA9ICh0YXNrQVJOOiBzdHJpbmcpOiBzdHJpbmcgPT4ge1xuICBjb25zdCBpbmRleE9mTGFzdFNsYXNoID0gdGFza0FSTi5sYXN0SW5kZXhPZihcIi9cIik7XG4gIGNvbnN0IHRhc2tOYW1lID0gdGFza0FSTi5zdWJzdHJpbmcoaW5kZXhPZkxhc3RTbGFzaCArIDEpO1xuICByZXR1cm4gdGFza05hbWU7XG59O1xuXG5jb25zdCBnZXRWdWxuZXJhYmxlRGlnZXN0c1BlckFSTiA9IGFzeW5jIChjbHVzdGVyQVJOOiBzdHJpbmcpOiBQcm9taXNlPGFueT4gPT4ge1xuICBjb25zdCB0YXNrTGlzdCA9IGF3YWl0IGxpc3RUYXNrc0Zyb21DbHVzdGVyQVJOKGNsdXN0ZXJBUk4pO1xuICBsZXQgdnVsbmVyYWJsZURpZ2VzdHM6IHsgW2tleTogc3RyaW5nXTogc3RyaW5nW10gfSA9IHt9O1xuICBpZiAodGFza0xpc3QgIT0gdW5kZWZpbmVkKSB7XG4gICAgY29uc3QgdGFza0lkTGlzdCA9IHRhc2tMaXN0Lm1hcCgodGFzazogc3RyaW5nKSA9PiBmb3JtYXRUYXNrTmFtZSh0YXNrKSk7XG4gICAgY29uc3QgaW5wdXQgPSB7XG4gICAgICB0YXNrczogdGFza0lkTGlzdCxcbiAgICAgIGNsdXN0ZXI6IGNsdXN0ZXJBUk4sXG4gICAgfTtcbiAgICBjb25zdCBjb21tYW5kID0gbmV3IERlc2NyaWJlVGFza3NDb21tYW5kKGlucHV0KTtcbiAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGVjcy5zZW5kKGNvbW1hbmQpO1xuICAgIGNvbnN0IGxpc3RPZlRhc2tzRnJvbVJlc3BvbnNlID0gcmVzcG9uc2UudGFza3M7XG4gICAgaWYgKGxpc3RPZlRhc2tzRnJvbVJlc3BvbnNlICE9IHVuZGVmaW5lZCkge1xuICAgICAgZm9yIChjb25zdCB0YXNrIG9mIGxpc3RPZlRhc2tzRnJvbVJlc3BvbnNlKSB7XG4gICAgICAgIGZvciAobGV0IG4gPSAwOyBuIDwgdGFzay5jb250YWluZXJzIS5sZW5ndGg7IG4rKykge1xuICAgICAgICAgIGlmICh0YXNrLmNvbnRhaW5lcnMhW25dLnRhc2tBcm4hIGluIHZ1bG5lcmFibGVEaWdlc3RzKSB7XG4gICAgICAgICAgICB2dWxuZXJhYmxlRGlnZXN0c1t0YXNrLmNvbnRhaW5lcnMhW25dLnRhc2tBcm4hXS5wdXNoKFxuICAgICAgICAgICAgICB0YXNrLmNvbnRhaW5lcnMhW25dLmltYWdlRGlnZXN0IVxuICAgICAgICAgICAgKTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdnVsbmVyYWJsZURpZ2VzdHNbdGFzay5jb250YWluZXJzIVtuXS50YXNrQXJuIV0gPSBbXG4gICAgICAgICAgICAgIHRhc2suY29udGFpbmVycyFbbl0uaW1hZ2VEaWdlc3QhLFxuICAgICAgICAgICAgXTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIHZ1bG5lcmFibGVEaWdlc3RzO1xuICB9XG4gIHJldHVybiB1bmRlZmluZWQ7XG59O1xuXG4vLyByZXR1cm5zIHRoZSBuYW1lIG9mIHRoZSBjbHVzdGVyIG9yIHVuZGVmaW5lZCBpZiBub3QgZm91bmRcbmNvbnN0IGdldENsdXN0ZXJOYW1lID0gYXN5bmMgKGNsdXN0ZXJBUk46IHN0cmluZyk6IFByb21pc2U8c3RyaW5nIHwgdW5kZWZpbmVkPiA9PiB7XG4gICAgY29uc3QgaW5wdXQgPSB7XG4gICAgICAgIGNsdXN0ZXJzOiBbY2x1c3RlckFSTl1cbiAgICB9XG4gICAgY29uc3QgY29tbWFuZCA9IG5ldyBEZXNjcmliZUNsdXN0ZXJzQ29tbWFuZChpbnB1dCk7XG4gICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBlY3Muc2VuZChjb21tYW5kKTtcbiAgICBpZiAocmVzcG9uc2UgIT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHJldHVybiByZXNwb25zZS5jbHVzdGVycyFbMF0uY2x1c3Rlck5hbWUhXG4gICAgfVxuICAgIHJldHVybiB1bmRlZmluZWRcbn0gXG5cbi8vIGZpbHRlcnMgbGlzdCBvZiB0YXNrcyB0byBqdXN0IHZ1bG5lcmFibGUgdGFza3NcbmNvbnN0IGdldFZ1bG5lcmFibGVUYXNrTGlzdCA9IGFzeW5jIChldmVudEltYWdlRGlnZXN0OiBzdHJpbmcsIGNsdXN0ZXJBUk46IHN0cmluZyk6IFByb21pc2U8c3RyaW5nW10gfCB1bmRlZmluZWQ+ID0+IHtcbiAgY29uc3QgdnVsbmVyYWJsZVRhc2tMaXN0OiBzdHJpbmdbXSA9IFtdO1xuICBjb25zdCBjbHVzdGVyTmFtZSA9IGF3YWl0IGdldENsdXN0ZXJOYW1lKGNsdXN0ZXJBUk4pO1xuICBjb25zdCB0YXNrTGlzdCA9IGF3YWl0IGxpc3RUYXNrc0Zyb21DbHVzdGVyQVJOKGNsdXN0ZXJBUk4pO1xuICAgIGlmICh0YXNrTGlzdCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIGNvbnNvbGUubG9nKGBObyBFQ1MgdGFza3MgZm91bmQgaW4gY2x1c3RlciAke2NsdXN0ZXJOYW1lfWApO1xuICAgIH0gZWxzZSB7XG4gICAgICBmb3IgKGNvbnN0IHRhc2sgb2YgdGFza0xpc3QpIHtcbiAgICAgICAgICBpZiAoZm9ybWF0VGFza05hbWUodGFzaykgPT09IGV2ZW50SW1hZ2VEaWdlc3QpIHtcbiAgICAgICAgICAgIHZ1bG5lcmFibGVUYXNrTGlzdC5wdXNoKHRhc2spO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgcmV0dXJuIHZ1bG5lcmFibGVUYXNrTGlzdDtcbiAgfVxuICByZXR1cm4gdW5kZWZpbmVkO1xufTsgXG5cblxuY29uc3QgY29tcGFyZURpZ2VzdHMgPSAoXG4gIGV2ZW50SW1hZ2VEaWdlc3Q6IHN0cmluZyxcbiAgaW1hZ2VEaWdlc3Q6IHN0cmluZ1xuKTogYm9vbGVhbiA9PiB7XG4gIHJldHVybiBldmVudEltYWdlRGlnZXN0ID09PSBpbWFnZURpZ2VzdDtcbn07XG5cbi8vIHRha2VzIGxpc3Qgb2YgdnVsbmVyYWJsZSB0YXNrIEFSTiBhbmQgZXZlbnRpbWFnZWRpZ2VzdFxuLy8gcHJpbnRzIHRoZSBjb250YWluZXIgbmFtZSBhbG9uZyB3aXRoIHRoZSB0YXNrIEFSTiBcbmNvbnN0IHByaW50TG9nTWVzc2FnZSA9IGFzeW5jIChsaXN0T2ZWdWxuZXJhYmxlVGFza3M6IHN0cmluZ1tdIHwgdW5kZWZpbmVkLCBldmVudEltZ0RpZ2VzdDogc3RyaW5nKSA9PiB7XG4gIGlmIChsaXN0T2ZWdWxuZXJhYmxlVGFza3MgPT0gdW5kZWZpbmVkKXtcbiAgICBjb25zb2xlLmxvZygnVnVsbmVyYWJsZSB0YXNrIGxpc3QgaXMgdW5kZWZpbmVkLicpXG4gIH0gZWxzZSBpZiAobGlzdE9mVnVsbmVyYWJsZVRhc2tzLmxlbmd0aCA9PT0gMCkge1xuICAgIGNvbnNvbGUubG9nKGBObyBFQ1MgdGFza3Mgd2l0aCB2dWxuZXJhYmxlIGltYWdlICR7ZXZlbnRJbWdEaWdlc3R9IGZvdW5kLmApO1xuICB9IGVsc2Uge1xuICAgIC8vIGZvciAoY29uc3QgdnVsbkRpZ2VzdCBvZiBsaXN0T2ZWdWxuZXJhYmxlVGFza3MpIHtcbiAgICAvLyAgIGlmIChjb21wYXJlRGlnZXN0cyh2dWxuRGlnZXN0LCBldmVudEltZ0RpZ2VzdCkpIHtcbiAgICAvLyAgICAgY29uc29sZS5sb2coXG4gICAgLy8gICAgICAgYEVDUyB0YXNrIHdpdGggdnVsbmVyYWJsZSBpbWFnZSAke2V2ZW50SW1nRGlnZXN0fSBmb3VuZDogJHt2dWxuRGlnZXN0fWBcbiAgICAvLyAgICAgKTtcbiAgICAvLyAgICAgY29uc29sZS5sb2coYCR7dnVsbkRpZ2VzdH1gKTtcbiAgICAvLyAgICAgLy8gcHJpbnQgdGhlIGVudGlyZSB0YXNrIGRlc2NyaXB0aW9uXG4gICAgLy8gICB9XG4gICAgLy8gfVxuICAgIGNvbnN0IGlucHV0ID0ge1xuICAgICAgICB0YXNrczogbGlzdE9mVnVsbmVyYWJsZVRhc2tzXG4gICAgfVxuICAgIGNvbnN0IGNvbW1hbmQgPSBuZXcgRGVzY3JpYmVUYXNrc0NvbW1hbmQoaW5wdXQpO1xuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4gICAgZm9yIChjb25zdCB0YXNrIG9mIHJlc3BvbnNlLnRhc2tzISkge1xuICAgICAgICBmb3IgKGNvbnN0IGNvbnRhaW5lciBvZiB0YXNrLmNvbnRhaW5lcnMhKSB7XG4gICAgICAgICAgICBpZiAoY29tcGFyZURpZ2VzdHMoY29udGFpbmVyLmltYWdlRGlnZXN0ISwgZXZlbnRJbWdEaWdlc3QpKSB7XG4gICAgICAgICAgICAgICAgLy8gcHJpbnQgdGhlIHRhc2sgQVJOXG4gICAgICAgICAgICAgICAgY29uc29sZS5sb2coYENvbnRhaW5lciAke2NvbnRhaW5lci5uYW1lfSBmb3VuZCB3aXRoXG4gICAgICAgICAgICAgICAgIHZ1bG5lcmFibGUgaW1hZ2UgJHtldmVudEltZ0RpZ2VzdH0uIFJlZmVyIHRvIHRhc2sgQVJOICR7dGFzay50YXNrQXJufWApXG4gICAgICAgICAgICAgICAgLy8gcHJpbnQgdGhlIGVudGlyZSBjb250YWluZXIgaW5mb3JtYXRpb25cbiAgICAgICAgICAgICAgICBjb25zb2xlLmxvZyhjb250YWluZXIpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0gICAgXG59O1xuXG5leHBvcnQgY29uc3QgaGFuZGxlciA9IGFzeW5jIGZ1bmN0aW9uIChcbiAgZXZlbnQ6IEV2ZW50QnJpZGdlRXZlbnQ8c3RyaW5nLCBhbnk+LFxuICBjb250ZXh0OiBDb250ZXh0LFxuICBjYWxsYmFjazogQ2FsbGJhY2tcbikge1xuICAvLyBjb25zb2xlLmxvZyhgXG4gIC8vICMjIyMjIyMjIyMjIyMjI1xuICAvLyAke0pTT04uc3RyaW5naWZ5KGV2ZW50KX1cbiAgLy8gIyMjIyMjIyMjIyMjIyMjXG4gIC8vIGApXG4gIGNvbnN0IGV2ZW50SW1hZ2VBUk46IHN0cmluZyA9IGV2ZW50LnJlc291cmNlc1swXTtcbiAgLy8gY29uc3QgZXZlbnRJbWFnZURpZ2VzdDogc3RyaW5nID0gZXZlbnQuZGV0YWlsLnJlc291cmNlcy5hd3NFY3JDb250YWluZXJJbWFnZS5pbWFnZUhhc2hcbiAgY29uc3QgZXZlbnRJbWFnZUFSTkRpZ2VzdEluZGV4ID0gZXZlbnRJbWFnZUFSTi5sYXN0SW5kZXhPZihcIi9zaGEyNTY6XCIpO1xuICBjb25zdCBldmVudEltYWdlRGlnZXN0ID0gZXZlbnRJbWFnZUFSTi5zbGljZShldmVudEltYWdlQVJORGlnZXN0SW5kZXggKyAxKTsgLy8gYWRkZWQgKyAxIHRvIHJlbW92ZSB0aGUgLyBpbiB0aGUgc3RyaW5nXG4gIC8vIGNvbnNvbGUubG9nKGBcbiAgLy8gIyMjIyMjIyMjIyMjIyMjXG4gIC8vIFRoaXMgaXMgdGhlIGV2ZW50IGltYWdlIGRpZ2VzdDogJHtldmVudEltYWdlRGlnZXN0fVxuICAvLyAjIyMjIyMjIyMjIyMjIyNcbiAgLy8gYCk7XG5cbiAgY29uc3QgY2x1c3Rlckxpc3QgPSBhd2FpdCBnZXRMaXN0T2ZDbHVzdGVyQVJOKCk7XG4gIGZvciAoY29uc3QgY2x1c3RlciBvZiBjbHVzdGVyTGlzdCkge1xuICAgIGNvbnN0IHZ1bG5SZXNvdXJjZXMgPSBhd2FpdCBnZXRWdWxuZXJhYmxlVGFza0xpc3QoZXZlbnRJbWFnZURpZ2VzdCxjbHVzdGVyKTtcbiAgICBwcmludExvZ01lc3NhZ2UodnVsblJlc291cmNlcywgZXZlbnRJbWFnZURpZ2VzdCk7XG4gIH1cbn1cbiJdfQ==