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
    console.log(`The list of tasks: ${taskList}`);
    // const input = {
    //   tasks: taskList,
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyJpbmRleC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFDQSxvREFNNkI7QUFFN0IsTUFBTSxHQUFHLEdBQUcsSUFBSSxzQkFBUyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0FBRTlCLE1BQU0sbUJBQW1CLEdBQUcsS0FBSyxJQUF1QixFQUFFO0lBQ3hELElBQUksV0FBVyxHQUFhLEVBQUUsQ0FBQztJQUMvQixJQUFJLFNBQTZCLENBQUM7SUFFbEMsTUFBTSxLQUFLLEdBQUcsRUFBRSxDQUFDO0lBQ2pCLE1BQU0sT0FBTyxHQUFHLElBQUksZ0NBQW1CLENBQUMsS0FBSyxDQUFDLENBQUM7SUFDL0MsR0FBRztRQUNELE1BQU0sUUFBUSxHQUFHLE1BQU0sR0FBRyxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsQ0FBQztRQUN6QyxnQkFBZ0I7UUFDaEIsb0JBQW9CO1FBQ3BCLHFEQUFxRDtRQUNyRCxvQkFBb0I7UUFDcEIsS0FBSztRQUNMLElBQUksUUFBUSxJQUFJLFNBQVMsRUFBRTtZQUN6QixnQ0FBZ0M7WUFDaEMsc0JBQXNCO1lBQ3RCLFNBQVMsR0FBRyxRQUFRLENBQUMsU0FBUyxDQUFDO1lBQy9CLFdBQVcsR0FBRyxXQUFXLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxXQUFZLENBQUMsQ0FBQztTQUN6RDtLQUNGLFFBQVEsU0FBUyxFQUFFO0lBQ3BCLE9BQU8sV0FBVyxDQUFDO0FBQ3JCLENBQUMsQ0FBQztBQUNGLHNEQUFzRDtBQUN0RCxNQUFNLHVCQUF1QixHQUFHLEtBQUssRUFBRSxXQUFtQixFQUFFLEVBQUU7SUFDNUQsSUFBSSxRQUFRLEdBQWEsRUFBRSxDQUFDO0lBQzVCLElBQUksU0FBNkIsQ0FBQztJQUVsQyxHQUFHO1FBQ0QsTUFBTSxLQUFLLEdBQUc7WUFDWixPQUFPLEVBQUUsV0FBVztTQUNyQixDQUFDO1FBQ0YsTUFBTSxPQUFPLEdBQUcsSUFBSSw2QkFBZ0IsQ0FBQyxL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LGNBQWMsdUJBQXVCLElBQUksQ0FBQyxPQUFPLEVBQUUsQ0FBQyxDQUFDO2dCQUNqRix5Q0FBeUM7Z0JBQ3pDLE9BQU8sQ0FBQyxHQUFHLENBQUMsU0FBUyxDQUFDLENBQUM7YUFDeEI7U0FDRjtLQUNGO0FBQ0gsQ0FBQyxDQUFDO0FBRUssTUFBTSxPQUFPLEdBQUcsS0FBSyxXQUMxQixLQUFvQyxFQUNwQyxPQUFnQixFQUNoQixRQUFrQjtJQUVsQixnQkFBZ0I7SUFDaEIsa0JBQWtCO0lBQ2xCLDJCQUEyQjtJQUMzQixrQkFBa0I7SUFDbEIsS0FBSztJQUNMLE1BQU0sYUFBYSxHQUFXLEtBQUssQ0FBQyxTQUFTLENBQUMsQ0FBQyxDQUFDLENBQUM7SUFDakQseUZBQXlGO0lBQ3pGLE1BQU0sd0JBQXdCLEdBQUcsYUFBYSxDQUFDLFdBQVcsQ0FBQyxVQUFVLENBQUMsQ0FBQztJQUN2RSxNQUFNLGdCQUFnQixHQUFHLGFBQWEsQ0FBQyxLQUFLLENBQUMsd0JBQXdCLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQywwQ0FBMEM7SUFDdEgsZ0JBQWdCO0lBQ2hCLGtCQUFrQjtJQUNsQixzREFBc0Q7SUFDdEQsa0JBQWtCO0lBQ2xCLE1BQU07SUFFTixNQUFNLFdBQVcsR0FBRyxNQUFNLG1CQUFtQixFQUFFLENBQUM7SUFDaEQsS0FBSyxNQUFNLE9BQU8sSUFBSSxXQUFXLEVBQUU7UUFDakMsTUFBTSxhQUFhLEdBQUcsTUFBTSxxQkFBcUIsQ0FDL0MsZ0JBQWdCLEVBQ2hCLE9BQU8sQ0FDUixDQUFDO1FBQ0YsZUFBZSxDQUFDLGFBQWEsRUFBRSxnQkFBZ0IsQ0FBQyxDQUFDO0tBQ2xEO0FBQ0gsQ0FBQyxDQUFDO0FBNUJXLFFBQUEsT0FBTyxXQTRCbEIiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBDYWxsYmFjaywgRXZlbnRCcmlkZ2VFdmVudCwgQ29udGV4dCB9IGZyb20gXCJhd3MtbGFtYmRhXCI7XG5pbXBvcnQge1xuICBFQ1NDbGllbnQsXG4gIExpc3RDbHVzdGVyc0NvbW1hbmQsXG4gIExpc3RUYXNrc0NvbW1hbmQsXG4gIERlc2NyaWJlVGFza3NDb21tYW5kLFxuICBEZXNjcmliZUNsdXN0ZXJzQ29tbWFuZCxcbn0gZnJvbSBcIkBhd3Mtc2RrL2NsaWVudC1lY3NcIjtcblxuY29uc3QgZWNzID0gbmV3IEVDU0NsaWVudCh7fSk7XG5cbmNvbnN0IGdldExpc3RPZkNsdXN0ZXJBUk4gPSBhc3luYyAoKTogUHJvbWlzZTxzdHJpbmdbXT4gPT4ge1xuICBsZXQgY2x1c3Rlckxpc3Q6IHN0cmluZ1tdID0gW107XG4gIGxldCBuZXh0VG9rZW46IHN0cmluZyB8IHVuZGVmaW5lZDtcblxuICBjb25zdCBpbnB1dCA9IHt9O1xuICBjb25zdCBjb21tYW5kID0gbmV3IExpc3RDbHVzdGVyc0NvbW1hbmQoaW5wdXQpO1xuICBkbyB7XG4gICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBlY3Muc2VuZChjb21tYW5kKTtcbiAgICAvLyBjb25zb2xlLmxvZyhgXG4gICAgLy8gICAgICMjIyMjIyMjIyMjIyNcbiAgICAvLyAgICAgbGlzdCBvZiBjbHVzdGVyczogICR7SlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpfVxuICAgIC8vICAgICAjIyMjIyMjIyMjIyMjXG4gICAgLy8gYClcbiAgICBpZiAocmVzcG9uc2UgIT0gdW5kZWZpbmVkKSB7XG4gICAgICAvLyByZXR1cm4gcmVzcG9uc2UuY2x1c3RlckFybnMhO1xuICAgICAgLy8gc2V0IG5leHQgdG9rZW4gaGVyZVxuICAgICAgbmV4dFRva2VuID0gcmVzcG9uc2UubmV4dFRva2VuO1xuICAgICAgY2x1c3Rlckxpc3QgPSBjbHVzdGVyTGlzdC5jb25jYXQocmVzcG9uc2UuY2x1c3RlckFybnMhKTtcbiAgICB9XG4gIH0gd2hpbGUgKG5leHRUb2tlbik7XG4gIHJldHVybiBjbHVzdGVyTGlzdDtcbn07XG4vLyByZXR1cm5zIGxpc3Qgb2YgQUxMIHRhc2sgQVJOIGZyb20gc3BlY2lmaWVkIGNsdXN0ZXJcbmNvbnN0IGxpc3RUYXNrc0Zyb21DbHVzdGVyQVJOID0gYXN5bmMgKGNsdXN0ZXJOYW1lOiBzdHJpbmcpID0+IHtcbiAgbGV0IHRhc2tMaXN0OiBzdHJpbmdbXSA9IFtdO1xuICBsZXQgbmV4dFRva2VuOiBzdHJpbmcgfCB1bmRlZmluZWQ7XG5cbiAgZG8ge1xuICAgIGNvbnN0IGlucHV0ID0ge1xuICAgICAgY2x1c3RlcjogY2x1c3Rlck5hbWUsXG4gICAgfTtcbiAgICBjb25zdCBjb21tYW5kID0gbmV3IExpc3RUYXNrc0NvbW1hbmQoaW5wdXQpO1xuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4gICAgLy8gY29uc29sZS5sb2coYFxuICAgIC8vICAgIyMjIyMjIyMjIyMjI1xuICAgIC8vICAgbGlzdCB0YXNrcyBmcm9tIGNsdXN0ZXIgYXJuOiAke3Jlc3BvbnNlLnRhc2tBcm5zfVxuICAgIC8vICAgIyMjIyMjIyMjIyMjI1xuICAgIC8vICAgYCk7XG4gICAgLy8gcmV0dXJuIHJlc3BvbnNlLnRhc2tBcm5zO1xuICAgIGlmIChyZXNwb25zZSAhPSB1bmRlZmluZWQpIHtcbiAgICAgIG5leHRUb2tlbiA9IHJlc3BvbnNlLm5leHRUb2tlbjtcbiAgICAgIHRhc2tMaXN0ID0gdGFza0xpc3QuY29uY2F0KHJlc3BvbnNlLnRhc2tBcm5zISk7XG4gICAgfVxuICB9IHdoaWxlIChuZXh0VG9rZW4pO1xuICByZXR1cm4gdGFza0xpc3Q7XG59O1xuXG4vLyBmb3JtYXRzIHRhc2sgQVJOIHRvIElEXG5jb25zdCBmb3JtYXRUYXNrTmFtZSA9ICh0YXNrQVJOOiBzdHJpbmcpOiBzdHJpbmcgPT4ge1xuICBjb25zdCBpbmRleE9mTGFzdFNsYXNoID0gdGFza0FSTi5sYXN0SW5kZXhPZihcIi9cIik7XG4gIGNvbnN0IHRhc2tOYW1lID0gdGFza0FSTi5zdWJzdHJpbmcoaW5kZXhPZkxhc3RTbGFzaCArIDEpO1xuICByZXR1cm4gdGFza05hbWU7XG59O1xuXG5jb25zdCBnZXRWdWxuZXJhYmxlRGlnZXN0c1BlckFSTiA9IGFzeW5jIChjbHVzdGVyQVJOOiBzdHJpbmcpOiBQcm9taXNlPGFueT4gPT4ge1xuICBjb25zdCB0YXNrTGlzdCA9IGF3YWl0IGxpc3RUYXNrc0Zyb21DbHVzdGVyQVJOKGNsdXN0ZXJBUk4pO1xuICBsZXQgdnVsbmVyYWJsZURpZ2VzdHM6IHsgW2tleTogc3RyaW5nXTogc3RyaW5nW10gfSA9IHt9O1xuICBpZiAodGFza0xpc3QgIT0gdW5kZWZpbmVkKSB7XG4gICAgY29uc3QgdGFza0lkTGlzdCA9IHRhc2tMaXN0Lm1hcCgodGFzazogc3RyaW5nKSA9PiBmb3JtYXRUYXNrTmFtZSh0YXNrKSk7XG4gICAgY29uc3QgaW5wdXQgPSB7XG4gICAgICB0YXNrczogdGFza0lkTGlzdCxcbiAgICAgIGNsdXN0ZXI6IGNsdXN0ZXJBUk4sXG4gICAgfTtcbiAgICBjb25zdCBjb21tYW5kID0gbmV3IERlc2NyaWJlVGFza3NDb21tYW5kKGlucHV0KTtcbiAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGVjcy5zZW5kKGNvbW1hbmQpO1xuICAgIGNvbnN0IGxpc3RPZlRhc2tzRnJvbVJlc3BvbnNlID0gcmVzcG9uc2UudGFza3M7XG4gICAgaWYgKGxpc3RPZlRhc2tzRnJvbVJlc3BvbnNlICE9IHVuZGVmaW5lZCkge1xuICAgICAgZm9yIChjb25zdCB0YXNrIG9mIGxpc3RPZlRhc2tzRnJvbVJlc3BvbnNlKSB7XG4gICAgICAgIGZvciAobGV0IG4gPSAwOyBuIDwgdGFzay5jb250YWluZXJzIS5sZW5ndGg7IG4rKykge1xuICAgICAgICAgIGlmICh0YXNrLmNvbnRhaW5lcnMhW25dLnRhc2tBcm4hIGluIHZ1bG5lcmFibGVEaWdlc3RzKSB7XG4gICAgICAgICAgICB2dWxuZXJhYmxlRGlnZXN0c1t0YXNrLmNvbnRhaW5lcnMhW25dLnRhc2tBcm4hXS5wdXNoKFxuICAgICAgICAgICAgICB0YXNrLmNvbnRhaW5lcnMhW25dLmltYWdlRGlnZXN0IVxuICAgICAgICAgICAgKTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdnVsbmVyYWJsZURpZ2VzdHNbdGFzay5jb250YWluZXJzIVtuXS50YXNrQXJuIV0gPSBbXG4gICAgICAgICAgICAgIHRhc2suY29udGFpbmVycyFbbl0uaW1hZ2VEaWdlc3QhLFxuICAgICAgICAgICAgXTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIHZ1bG5lcmFibGVEaWdlc3RzO1xuICB9XG4gIHJldHVybiB1bmRlZmluZWQ7XG59O1xuXG4vLyByZXR1cm5zIHRoZSBuYW1lIG9mIHRoZSBjbHVzdGVyIG9yIHVuZGVmaW5lZCBpZiBub3QgZm91bmRcbmNvbnN0IGdldENsdXN0ZXJOYW1lID0gYXN5bmMgKFxuICBjbHVzdGVyQVJOOiBzdHJpbmdcbik6IFByb21pc2U8c3RyaW5nIHwgdW5kZWZpbmVkPiA9PiB7XG4gIGNvbnN0IGlucHV0ID0ge1xuICAgIGNsdXN0ZXJzOiBbY2x1c3RlckFSTl0sXG4gIH07XG4gIGNvbnN0IGNvbW1hbmQgPSBuZXcgRGVzY3JpYmVDbHVzdGVyc0NvbW1hbmQoaW5wdXQpO1xuICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGVjcy5zZW5kKGNvbW1hbmQpO1xuICBpZiAocmVzcG9uc2UgIT0gdW5kZWZpbmVkKSB7XG4gICAgcmV0dXJuIHJlc3BvbnNlLmNsdXN0ZXJzIVswXS5jbHVzdGVyTmFtZSE7XG4gIH1cbiAgcmV0dXJuIHVuZGVmaW5lZDtcbn07XG5cbi8vIGZpbHRlcnMgbGlzdCBvZiB0YXNrcyB0byBqdXN0IHZ1bG5lcmFibGUgdGFza3Ncbi8vIHRyeSB3aXRoIGp1c3QgcmV0dXJuaW5nIGEgdGFza2xpc3RcbmNvbnN0IGdldFZ1bG5lcmFibGVUYXNrTGlzdCA9IGFzeW5jIChcbiAgZXZlbnRJbWFnZURpZ2VzdDogc3RyaW5nLFxuICBjbHVzdGVyQVJOOiBzdHJpbmdcbik6IFByb21pc2U8c3RyaW5nW10gfCB1bmRlZmluZWQ+ID0+IHtcbiAgY29uc3QgdnVsbmVyYWJsZVRhc2tMaXN0OiBzdHJpbmdbXSA9IFtdO1xuICBjb25zdCBjbHVzdGVyTmFtZSA9IGF3YWl0IGdldENsdXN0ZXJOYW1lKGNsdXN0ZXJBUk4pO1xuICBjb25zdCB0YXNrTGlzdCA9IGF3YWl0IGxpc3RUYXNrc0Zyb21DbHVzdGVyQVJOKGNsdXN0ZXJBUk4pO1xuICBjb25zb2xlLmxvZyhgVGhlIGxpc3Qgb2YgdGFza3M6ICR7dGFza0xpc3R9YClcbiAgLy8gY29uc3QgaW5wdXQgPSB7XG4gIC8vICAgdGFza3M6IHRhc2tMaXN0LFxuICAvLyB9O1xuICAvLyBjb25zdCBjb21tYW5kID0gbmV3IERlc2NyaWJlVGFza3NDb21tYW5kKGlucHV0KTtcbiAgLy8gY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBlY3Muc2VuZChjb21tYW5kKTtcbiAgLy8gY29uc29sZS5sb2cocmVzcG9uc2UpO1xuICBpZiAodGFza0xpc3QgPT09IHVuZGVmaW5lZCkge1xuICAgIGNvbnNvbGUubG9nKGBObyBFQ1MgdGFza3MgZm91bmQgaW4gY2x1c3RlciAke2NsdXN0ZXJOYW1lfWApO1xuICB9IGVsc2Uge1xuICAgIGZvciAoY29uc3QgdGFzayBvZiB0YXNrTGlzdCkge1xuICAgICAgY29uc29sZS5sb2codGFzayk7XG4gICAgICBjb25zb2xlLmxvZyhmb3JtYXRUYXNrTmFtZSh0YXNrKSk7XG4gICAgICBpZiAoZm9ybWF0VGFza05hbWUodGFzaykgPT09IGV2ZW50SW1hZ2VEaWdlc3QpIHtcbiAgICAgICAgdnVsbmVyYWJsZVRhc2tMaXN0LnB1c2godGFzayk7XG4gICAgICB9XG4gICAgfVxuICAgIGNvbnNvbGUubG9nKHZ1bG5lcmFibGVUYXNrTGlzdCk7XG4gICAgcmV0dXJuIHZ1bG5lcmFibGVUYXNrTGlzdDtcbiAgfVxuICByZXR1cm4gdW5kZWZpbmVkO1xufTtcblxuY29uc3QgY29tcGFyZURpZ2VzdHMgPSAoXG4gIGV2ZW50SW1hZ2VEaWdlc3Q6IHN0cmluZyxcbiAgaW1hZ2VEaWdlc3Q6IHN0cmluZ1xuKTogYm9vbGVhbiA9PiB7XG4gIHJldHVybiBldmVudEltYWdlRGlnZXN0ID09PSBpbWFnZURpZ2VzdDtcbn07XG5cbi8vIHRha2VzIGxpc3Qgb2YgdnVsbmVyYWJsZSB0YXNrIEFSTiBhbmQgZXZlbnRpbWFnZWRpZ2VzdFxuLy8gcHJpbnRzIHRoZSBjb250YWluZXIgbmFtZSBhbG9uZyB3aXRoIHRoZSB0YXNrIEFSTlxuY29uc3QgcHJpbnRMb2dNZXNzYWdlID0gYXN5bmMgKFxuICBsaXN0T2ZWdWxuZXJhYmxlVGFza3M6IHN0cmluZ1tdIHwgdW5kZWZpbmVkLFxuICBldmVudEltZ0RpZ2VzdDogc3RyaW5nXG4pID0+IHtcbiAgaWYgKGxpc3RPZlZ1bG5lcmFibGVUYXNrcyA9PSB1bmRlZmluZWQpIHtcbiAgICBjb25zb2xlLmxvZyhcIlZ1bG5lcmFibGUgdGFzayBsaXN0IGlzIHVuZGVmaW5lZC5cIik7XG4gIH0gZWxzZSBpZiAobGlzdE9mVnVsbmVyYWJsZVRhc2tzLmxlbmd0aCA9PT0gMCkge1xuICAgIGNvbnNvbGUubG9nKGBObyBFQ1MgdGFza3Mgd2l0aCB2dWxuZXJhYmxlIGltYWdlICR7ZXZlbnRJbWdEaWdlc3R9IGZvdW5kLmApO1xuICB9IGVsc2Uge1xuICAgIC8vIGZvciAoY29uc3QgdnVsbkRpZ2VzdCBvZiBsaXN0T2ZWdWxuZXJhYmxlVGFza3MpIHtcbiAgICAvLyAgIGlmIChjb21wYXJlRGlnZXN0cyh2dWxuRGlnZXN0LCBldmVudEltZ0RpZ2VzdCkpIHtcbiAgICAvLyAgICAgY29uc29sZS5sb2coXG4gICAgLy8gICAgICAgYEVDUyB0YXNrIHdpdGggdnVsbmVyYWJsZSBpbWFnZSAke2V2ZW50SW1nRGlnZXN0fSBmb3VuZDogJHt2dWxuRGlnZXN0fWBcbiAgICAvLyAgICAgKTtcbiAgICAvLyAgICAgY29uc29sZS5sb2coYCR7dnVsbkRpZ2VzdH1gKTtcbiAgICAvLyAgICAgLy8gcHJpbnQgdGhlIGVudGlyZSB0YXNrIGRlc2NyaXB0aW9uXG4gICAgLy8gICB9XG4gICAgLy8gfVxuICAgIGNvbnN0IGlucHV0ID0ge1xuICAgICAgdGFza3M6IGxpc3RPZlZ1bG5lcmFibGVUYXNrcyxcbiAgICB9O1xuICAgIGNvbnN0IGNvbW1hbmQgPSBuZXcgRGVzY3JpYmVUYXNrc0NvbW1hbmQoaW5wdXQpO1xuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4gICAgZm9yIChjb25zdCB0YXNrIG9mIHJlc3BvbnNlLnRhc2tzISkge1xuICAgICAgZm9yIChjb25zdCBjb250YWluZXIgb2YgdGFzay5jb250YWluZXJzISkge1xuICAgICAgICAvLyBwcmludCB0aGUgdGFzayBBUk5cbiAgICAgICAgY29uc29sZS5sb2coYENvbnRhaW5lciAke2NvbnRhaW5lci5uYW1lfSBmb3VuZCB3aXRoXG4gICAgICAgICAgICAgICAgIHZ1bG5lcmFibGUgaW1hZ2UgJHtldmVudEltZ0RpZ2VzdH0uIFJlZmVyIHRvIHRhc2sgQVJOICR7dGFzay50YXNrQXJufWApO1xuICAgICAgICAvLyBwcmludCB0aGUgZW50aXJlIGNvbnRhaW5lciBpbmZvcm1hdGlvblxuICAgICAgICBjb25zb2xlLmxvZyhjb250YWluZXIpO1xuICAgICAgfVxuICAgIH1cbiAgfVxufTtcblxuZXhwb3J0IGNvbnN0IGhhbmRsZXIgPSBhc3luYyBmdW5jdGlvbiAoXG4gIGV2ZW50OiBFdmVudEJyaWRnZUV2ZW50PHN0cmluZywgYW55PixcbiAgY29udGV4dDogQ29udGV4dCxcbiAgY2FsbGJhY2s6IENhbGxiYWNrXG4pIHtcbiAgLy8gY29uc29sZS5sb2coYFxuICAvLyAjIyMjIyMjIyMjIyMjIyNcbiAgLy8gJHtKU09OLnN0cmluZ2lmeShldmVudCl9XG4gIC8vICMjIyMjIyMjIyMjIyMjI1xuICAvLyBgKVxuICBjb25zdCBldmVudEltYWdlQVJOOiBzdHJpbmcgPSBldmVudC5yZXNvdXJjZXNbMF07XG4gIC8vIGNvbnN0IGV2ZW50SW1hZ2VEaWdlc3Q6IHN0cmluZyA9IGV2ZW50LmRldGFpbC5yZXNvdXJjZXMuYXdzRWNyQ29udGFpbmVySW1hZ2UuaW1hZ2VIYXNoXG4gIGNvbnN0IGV2ZW50SW1hZ2VBUk5EaWdlc3RJbmRleCA9IGV2ZW50SW1hZ2VBUk4ubGFzdEluZGV4T2YoXCIvc2hhMjU2OlwiKTtcbiAgY29uc3QgZXZlbnRJbWFnZURpZ2VzdCA9IGV2ZW50SW1hZ2VBUk4uc2xpY2UoZXZlbnRJbWFnZUFSTkRpZ2VzdEluZGV4ICsgMSk7IC8vIGFkZGVkICsgMSB0byByZW1vdmUgdGhlIC8gaW4gdGhlIHN0cmluZ1xuICAvLyBjb25zb2xlLmxvZyhgXG4gIC8vICMjIyMjIyMjIyMjIyMjI1xuICAvLyBUaGlzIGlzIHRoZSBldmVudCBpbWFnZSBkaWdlc3Q6ICR7ZXZlbnRJbWFnZURpZ2VzdH1cbiAgLy8gIyMjIyMjIyMjIyMjIyMjXG4gIC8vIGApO1xuXG4gIGNvbnN0IGNsdXN0ZXJMaXN0ID0gYXdhaXQgZ2V0TGlzdE9mQ2x1c3RlckFSTigpO1xuICBmb3IgKGNvbnN0IGNsdXN0ZXIgb2YgY2x1c3Rlckxpc3QpIHtcbiAgICBjb25zdCB2dWxuUmVzb3VyY2VzID0gYXdhaXQgZ2V0VnVsbmVyYWJsZVRhc2tMaXN0KFxuICAgICAgZXZlbnRJbWFnZURpZ2VzdCxcbiAgICAgIGNsdXN0ZXJcbiAgICApO1xuICAgIHByaW50TG9nTWVzc2FnZSh2dWxuUmVzb3VyY2VzLCBldmVudEltYWdlRGlnZXN0KTtcbiAgfVxufTtcbiJdfQ==