"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.handler = void 0;
const client_ecs_1 = require("@aws-sdk/client-ecs");
const ecs = new client_ecs_1.ECSClient({});
// returns list of cluster ARN
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
            if (response.taskArns != undefined) {
                taskList = taskList.concat(response.taskArns);
            }
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
const getTaskDescriptions = async (clusterARN, taskIdList) => {
    const input = {
        tasks: taskIdList,
        cluster: clusterARN
    };
    const command = new client_ecs_1.DescribeTasksCommand(input);
    const response = await ecs.send(command);
    if (response != undefined) {
        return response.tasks;
    }
    return undefined;
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
// const printLogMessage = async (
//   listOfVulnerableTasks: string[] | undefined,
//   eventImgDigest: string
// ) => {
//   if (listOfVulnerableTasks == undefined) {
//     console.log("Vulnerable task list is undefined.");
//   } else if (listOfVulnerableTasks.length === 0) {
//     console.log(`No ECS tasks with vulnerable image ${eventImgDigest} found.`);
//   } else {
//     // for (const vulnDigest of listOfVulnerableTasks) {
//     //   if (compareDigests(vulnDigest, eventImgDigest)) {
//     //     console.log(
//     //       `ECS task with vulnerable image ${eventImgDigest} found: ${vulnDigest}`
//     //     );
//     //     console.log(`${vulnDigest}`);
//     //     // print the entire task description
//     //   }
//     // }
//     const input = {
//       tasks: listOfVulnerableTasks,
//     };
//     const command = new DescribeTasksCommand(input);
//     const response = await ecs.send(command);
//     for (const task of response.tasks!) {
//       for (const container of task.containers!) {
//         // print the task ARN
//         console.log(`Container ${container.name} found with
//                  vulnerable image ${eventImgDigest}. Refer to task ARN ${task.taskArn}`);
//         // print the entire container information
//         console.log(container);
//       }
//     }
//   }
// };
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
    const clusterList = await getListOfClusterARN(); // get list of clusters
    let allTasks; // empty list to hold all task descriptions
    for (const cluster of clusterList) {
        const taskIds = await listTasksFromClusterARN(cluster); // getting all task ids per cluster
        if (taskIds != undefined) {
            const taskDescriptions = await getTaskDescriptions(cluster, taskIds); // getting all task descriptions per cluster
            allTasks = allTasks.concat(taskDescriptions);
        }
    }
    for (const task of allTasks) {
        if (task.containers) {
            for (const container of task.containers) {
                if (compareDigests(container.imageDigest, eventImageDigest)) {
                    console.log(`${container.name} has been found to have a new vulnerability. The associated image can be found here: ${container.image}}`);
                }
            }
        }
    }
};
exports.handler = handler;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyJpbmRleC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFDQSxvREFPNkI7QUFHN0IsTUFBTSxHQUFHLEdBQUcsSUFBSSxzQkFBUyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0FBRTlCLDhCQUE4QjtBQUM5QixNQUFNLG1CQUFtQixHQUFHLEtBQUssSUFBdUIsRUFBRTtJQUN4RCxJQUFJLFdBQVcsR0FBYSxFQUFFLENBQUM7SUFDL0IsSUFBSSxTQUE2QixDQUFDO0lBRWxDLE1BQU0sS0FBSyxHQUFHLEVBQUUsQ0FBQztJQUNqQixNQUFNLE9BQU8sR0FBRyxJQUFJLGdDQUFtQixDQUFDLEtBQUssQ0FBQyxDQUFDO0lBQy9DLEdBQUc7UUFDRCxNQUFNLFFBQVEsR0FBRyxNQUFNLEdBQUcsQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUM7UUFDekMsZ0JBQWdCO1FBQ2hCLG9CQUFvQjtRQUNwQixxREFBcUQ7UUFDckQsb0JBQW9CO1FBQ3BCLEtBQUs7UUFDTCxJQUFJLFFBQVEsSUFBSSxTQUFTLEVBQUU7WUFDekIsZ0NBQWdDO1lBQ2hDLHNCQUFzQjtZQUN0QixTQUFTLEdBQUcsUUFBUSxDQUFDLFNBQVMsQ0FBQztZQUMvQixXQUFXLEdBQUcsV0FBVyxDQUFDLE1BQU0sQ0FBQyxRQUFRLENBQUMsV0FBWSxDQUFDLENBQUM7U0FDekQ7S0FDRixRQUFRLFNBQVMsRUFBRTtJQUNwQixPQUFPLFdBQVcsQ0FBQztBQUNyQixDQUFDLENBQUM7QUFFRixzREFBc0Q7QUFDdEQsTUFBTSx1QkFBdUIsR0FBRyxLQUFLLEVBQUUsV0FBbUIsRUFBRSxFQUFFO0lBQzVELElBQUksUUFBUSxHQUFhLEVBQUUsQ0FBQztJQUM1QixJQUFJLFNBQTZCLENBQUM7SUFFbEMsR0FBRztRQUNELE1BQU0sS0FBSyxHQUFHO1lBQ1osT0FBTyxFQUFFLFdBQVc7U0FDckIsQ0FBQztRQUNGLE1BQU0sT0FBTyxHQUFHLElBQUks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aUIsQ0FBRSxDQUFDLDJDQUEyQztJQUNuRSxLQUFLLE1BQU0sT0FBTyxJQUFJLFdBQVcsRUFBRTtRQUNqQyxNQUFNLE9BQU8sR0FBRyxNQUFNLHVCQUF1QixDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsbUNBQW1DO1FBQzNGLElBQUksT0FBTyxJQUFJLFNBQVMsRUFBRTtZQUN4QixNQUFNLGdCQUFnQixHQUFHLE1BQU0sbUJBQW1CLENBQUMsT0FBTyxFQUFFLE9BQU8sQ0FBQyxDQUFDLENBQUMsNENBQTRDO1lBQ2xILFFBQVEsR0FBRyxRQUFTLENBQUMsTUFBTSxDQUFDLGdCQUFpQixDQUFDLENBQUM7U0FDaEQ7S0FDRjtJQUNELEtBQUssTUFBTSxJQUFJLElBQUksUUFBUyxFQUFFO1FBQzVCLElBQUksSUFBSSxDQUFDLFVBQVUsRUFBQztZQUNsQixLQUFLLE1BQU0sU0FBUyxJQUFJLElBQUksQ0FBQyxVQUFXLEVBQUU7Z0JBQ3hDLElBQUksY0FBYyxDQUFDLFNBQVMsQ0FBQyxXQUFZLEVBQUUsZ0JBQWdCLENBQUMsRUFBRTtvQkFDNUQsT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLFNBQVMsQ0FBQyxJQUFJLHdGQUF3RixTQUFTLENBQUMsS0FBSyxHQUFHLENBQUMsQ0FBQTtpQkFDekk7YUFDRjtTQUNGO0tBQ0Y7QUFDSCxDQUFDLENBQUM7QUF0Q1csUUFBQSxPQUFPLFdBc0NsQiIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IENhbGxiYWNrLCBFdmVudEJyaWRnZUV2ZW50LCBDb250ZXh0IH0gZnJvbSBcImF3cy1sYW1iZGFcIjtcbmltcG9ydCB7XG4gIEVDU0NsaWVudCxcbiAgTGlzdENsdXN0ZXJzQ29tbWFuZCxcbiAgTGlzdFRhc2tzQ29tbWFuZCxcbiAgRGVzY3JpYmVUYXNrc0NvbW1hbmQsXG4gIERlc2NyaWJlQ2x1c3RlcnNDb21tYW5kLFxuICBUYXNrXG59IGZyb20gXCJAYXdzLXNkay9jbGllbnQtZWNzXCI7XG5pbXBvcnQgeyBUYXNrRGVmaW5pdGlvbiB9IGZyb20gXCJhd3MtY2RrLWxpYi9hd3MtZWNzXCI7XG5cbmNvbnN0IGVjcyA9IG5ldyBFQ1NDbGllbnQoe30pO1xuXG4vLyByZXR1cm5zIGxpc3Qgb2YgY2x1c3RlciBBUk5cbmNvbnN0IGdldExpc3RPZkNsdXN0ZXJBUk4gPSBhc3luYyAoKTogUHJvbWlzZTxzdHJpbmdbXT4gPT4ge1xuICBsZXQgY2x1c3Rlckxpc3Q6IHN0cmluZ1tdID0gW107XG4gIGxldCBuZXh0VG9rZW46IHN0cmluZyB8IHVuZGVmaW5lZDtcblxuICBjb25zdCBpbnB1dCA9IHt9O1xuICBjb25zdCBjb21tYW5kID0gbmV3IExpc3RDbHVzdGVyc0NvbW1hbmQoaW5wdXQpO1xuICBkbyB7XG4gICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBlY3Muc2VuZChjb21tYW5kKTtcbiAgICAvLyBjb25zb2xlLmxvZyhgXG4gICAgLy8gICAgICMjIyMjIyMjIyMjIyNcbiAgICAvLyAgICAgbGlzdCBvZiBjbHVzdGVyczogICR7SlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpfVxuICAgIC8vICAgICAjIyMjIyMjIyMjIyMjXG4gICAgLy8gYClcbiAgICBpZiAocmVzcG9uc2UgIT0gdW5kZWZpbmVkKSB7XG4gICAgICAvLyByZXR1cm4gcmVzcG9uc2UuY2x1c3RlckFybnMhO1xuICAgICAgLy8gc2V0IG5leHQgdG9rZW4gaGVyZVxuICAgICAgbmV4dFRva2VuID0gcmVzcG9uc2UubmV4dFRva2VuO1xuICAgICAgY2x1c3Rlckxpc3QgPSBjbHVzdGVyTGlzdC5jb25jYXQocmVzcG9uc2UuY2x1c3RlckFybnMhKTtcbiAgICB9XG4gIH0gd2hpbGUgKG5leHRUb2tlbik7XG4gIHJldHVybiBjbHVzdGVyTGlzdDtcbn07XG5cbi8vIHJldHVybnMgbGlzdCBvZiBBTEwgdGFzayBBUk4gZnJvbSBzcGVjaWZpZWQgY2x1c3RlclxuY29uc3QgbGlzdFRhc2tzRnJvbUNsdXN0ZXJBUk4gPSBhc3luYyAoY2x1c3Rlck5hbWU6IHN0cmluZykgPT4ge1xuICBsZXQgdGFza0xpc3Q6IHN0cmluZ1tdID0gW107XG4gIGxldCBuZXh0VG9rZW46IHN0cmluZyB8IHVuZGVmaW5lZDtcblxuICBkbyB7XG4gICAgY29uc3QgaW5wdXQgPSB7XG4gICAgICBjbHVzdGVyOiBjbHVzdGVyTmFtZSxcbiAgICB9O1xuICAgIGNvbnN0IGNvbW1hbmQgPSBuZXcgTGlzdFRhc2tzQ29tbWFuZChpbnB1dCk7XG4gICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBlY3Muc2VuZChjb21tYW5kKTtcbiAgICAvLyBjb25zb2xlLmxvZyhgXG4gICAgLy8gICAjIyMjIyMjIyMjIyMjXG4gICAgLy8gICBsaXN0IHRhc2tzIGZyb20gY2x1c3RlciBhcm46ICR7cmVzcG9uc2UudGFza0FybnN9XG4gICAgLy8gICAjIyMjIyMjIyMjIyMjXG4gICAgLy8gICBgKTtcbiAgICAvLyByZXR1cm4gcmVzcG9uc2UudGFza0FybnM7XG4gICAgaWYgKHJlc3BvbnNlICE9IHVuZGVmaW5lZCkge1xuICAgICAgbmV4dFRva2VuID0gcmVzcG9uc2UubmV4dFRva2VuO1xuICAgICAgaWYgKHJlc3BvbnNlLnRhc2tBcm5zICE9IHVuZGVmaW5lZCkge1xuICAgICAgICB0YXNrTGlzdCA9IHRhc2tMaXN0LmNvbmNhdChyZXNwb25zZS50YXNrQXJucyk7XG4gICAgICB9XG4gICAgfVxuICB9IHdoaWxlIChuZXh0VG9rZW4pO1xuICByZXR1cm4gdGFza0xpc3Q7XG59O1xuXG4vLyBmb3JtYXRzIHRhc2sgQVJOIHRvIElEXG5jb25zdCBmb3JtYXRUYXNrTmFtZSA9ICh0YXNrQVJOOiBzdHJpbmcpOiBzdHJpbmcgPT4ge1xuICBjb25zdCBpbmRleE9mTGFzdFNsYXNoID0gdGFza0FSTi5sYXN0SW5kZXhPZihcIi9cIik7XG4gIGNvbnN0IHRhc2tOYW1lID0gdGFza0FSTi5zdWJzdHJpbmcoaW5kZXhPZkxhc3RTbGFzaCArIDEpO1xuICByZXR1cm4gdGFza05hbWU7XG59O1xuXG5jb25zdCBnZXRUYXNrRGVzY3JpcHRpb25zID0gYXN5bmMgKGNsdXN0ZXJBUk46c3RyaW5nLCB0YXNrSWRMaXN0OiBzdHJpbmdbXSk6IFByb21pc2U8VGFza1tdIHwgdW5kZWZpbmVkPiA9PiB7XG4gIGNvbnN0IGlucHV0ID0ge1xuICAgIHRhc2tzOiB0YXNrSWRMaXN0LFxuICAgIGNsdXN0ZXI6IGNsdXN0ZXJBUk5cbiAgfVxuICBjb25zdCBjb21tYW5kID0gbmV3IERlc2NyaWJlVGFza3NDb21tYW5kKGlucHV0KTtcbiAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBlY3Muc2VuZChjb21tYW5kKTtcbiAgaWYgKHJlc3BvbnNlICE9IHVuZGVmaW5lZCkge1xuICAgIHJldHVybiByZXNwb25zZS50YXNrcztcbiAgfVxuICByZXR1cm4gdW5kZWZpbmVkO1xufVxuXG5jb25zdCBnZXRWdWxuZXJhYmxlRGlnZXN0c1BlckFSTiA9IGFzeW5jIChjbHVzdGVyQVJOOiBzdHJpbmcpOiBQcm9taXNlPGFueT4gPT4ge1xuICBjb25zdCB0YXNrTGlzdCA9IGF3YWl0IGxpc3RUYXNrc0Zyb21DbHVzdGVyQVJOKGNsdXN0ZXJBUk4pO1xuICBsZXQgdnVsbmVyYWJsZURpZ2VzdHM6IHsgW2tleTogc3RyaW5nXTogc3RyaW5nW10gfSA9IHt9O1xuICBpZiAodGFza0xpc3QgIT0gdW5kZWZpbmVkKSB7XG4gICAgY29uc3QgdGFza0lkTGlzdCA9IHRhc2tMaXN0Lm1hcCgodGFzazogc3RyaW5nKSA9PiBmb3JtYXRUYXNrTmFtZSh0YXNrKSk7XG4gICAgY29uc3QgaW5wdXQgPSB7XG4gICAgICB0YXNrczogdGFza0lkTGlzdCxcbiAgICAgIGNsdXN0ZXI6IGNsdXN0ZXJBUk4sXG4gICAgfTtcbiAgICBjb25zdCBjb21tYW5kID0gbmV3IERlc2NyaWJlVGFza3NDb21tYW5kKGlucHV0KTtcbiAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGVjcy5zZW5kKGNvbW1hbmQpO1xuICAgIGNvbnN0IGxpc3RPZlRhc2tzRnJvbVJlc3BvbnNlID0gcmVzcG9uc2UudGFza3M7XG4gICAgaWYgKGxpc3RPZlRhc2tzRnJvbVJlc3BvbnNlICE9IHVuZGVmaW5lZCkge1xuICAgICAgZm9yIChjb25zdCB0YXNrIG9mIGxpc3RPZlRhc2tzRnJvbVJlc3BvbnNlKSB7XG4gICAgICAgIGZvciAobGV0IG4gPSAwOyBuIDwgdGFzay5jb250YWluZXJzIS5sZW5ndGg7IG4rKykge1xuICAgICAgICAgIGlmICh0YXNrLmNvbnRhaW5lcnMhW25dLnRhc2tBcm4hIGluIHZ1bG5lcmFibGVEaWdlc3RzKSB7XG4gICAgICAgICAgICB2dWxuZXJhYmxlRGlnZXN0c1t0YXNrLmNvbnRhaW5lcnMhW25dLnRhc2tBcm4hXS5wdXNoKFxuICAgICAgICAgICAgICB0YXNrLmNvbnRhaW5lcnMhW25dLmltYWdlRGlnZXN0IVxuICAgICAgICAgICAgKTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdnVsbmVyYWJsZURpZ2VzdHNbdGFzay5jb250YWluZXJzIVtuXS50YXNrQXJuIV0gPSBbXG4gICAgICAgICAgICAgIHRhc2suY29udGFpbmVycyFbbl0uaW1hZ2VEaWdlc3QhLFxuICAgICAgICAgICAgXTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIHZ1bG5lcmFibGVEaWdlc3RzO1xuICB9XG4gIHJldHVybiB1bmRlZmluZWQ7XG59O1xuXG4vLyByZXR1cm5zIHRoZSBuYW1lIG9mIHRoZSBjbHVzdGVyIG9yIHVuZGVmaW5lZCBpZiBub3QgZm91bmRcbmNvbnN0IGdldENsdXN0ZXJOYW1lID0gYXN5bmMgKFxuICBjbHVzdGVyQVJOOiBzdHJpbmdcbik6IFByb21pc2U8c3RyaW5nIHwgdW5kZWZpbmVkPiA9PiB7XG4gIGNvbnN0IGlucHV0ID0ge1xuICAgIGNsdXN0ZXJzOiBbY2x1c3RlckFSTl0sXG4gIH07XG4gIGNvbnN0IGNvbW1hbmQgPSBuZXcgRGVzY3JpYmVDbHVzdGVyc0NvbW1hbmQoaW5wdXQpO1xuICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGVjcy5zZW5kKGNvbW1hbmQpO1xuICBpZiAocmVzcG9uc2UgIT0gdW5kZWZpbmVkKSB7XG4gICAgcmV0dXJuIHJlc3BvbnNlLmNsdXN0ZXJzIVswXS5jbHVzdGVyTmFtZSE7XG4gIH1cbiAgcmV0dXJuIHVuZGVmaW5lZDtcbn07XG5cbi8vIGZpbHRlcnMgbGlzdCBvZiB0YXNrcyB0byBqdXN0IHZ1bG5lcmFibGUgdGFza3Ncbi8vIHRyeSB3aXRoIGp1c3QgcmV0dXJuaW5nIGEgdGFza2xpc3RcbmNvbnN0IGdldFZ1bG5lcmFibGVUYXNrTGlzdCA9IGFzeW5jIChcbiAgZXZlbnRJbWFnZURpZ2VzdDogc3RyaW5nLFxuICBjbHVzdGVyQVJOOiBzdHJpbmdcbik6IFByb21pc2U8c3RyaW5nW10gfCB1bmRlZmluZWQ+ID0+IHtcbiAgY29uc3QgdnVsbmVyYWJsZVRhc2tMaXN0OiBzdHJpbmdbXSA9IFtdO1xuICBjb25zdCBjbHVzdGVyTmFtZSA9IGF3YWl0IGdldENsdXN0ZXJOYW1lKGNsdXN0ZXJBUk4pO1xuICBjb25zdCB0YXNrTGlzdCA9IGF3YWl0IGxpc3RUYXNrc0Zyb21DbHVzdGVyQVJOKGNsdXN0ZXJBUk4pO1xuICBjb25zb2xlLmxvZyhgVGhlIGxpc3Qgb2YgdGFza3M6ICR7dGFza0xpc3QubWFwKCh0YXNrKT0+Zm9ybWF0VGFza05hbWUodGFzaykpfWApXG4gIGNvbnN0IGZvcm1hdHRlZFRhc2tzID0gdGFza0xpc3QubWFwKCh0YXNrKT0+Zm9ybWF0VGFza05hbWUodGFzaykpO1xuICBjb25zdCBpbnB1dCA9IHtcbiAgICB0YXNrczogZm9ybWF0dGVkVGFza3MsXG4gIH07XG4gIGNvbnN0IGNvbW1hbmQgPSBuZXcgRGVzY3JpYmVUYXNrc0NvbW1hbmQoaW5wdXQpO1xuICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGVjcy5zZW5kKGNvbW1hbmQpO1xuICBjb25zb2xlLmxvZyhyZXNwb25zZSk7XG4gIGlmICh0YXNrTGlzdCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgY29uc29sZS5sb2coYE5vIEVDUyB0YXNrcyBmb3VuZCBpbiBjbHVzdGVyICR7Y2x1c3Rlck5hbWV9YCk7XG4gIH0gZWxzZSB7XG4gICAgZm9yIChjb25zdCB0YXNrIG9mIHRhc2tMaXN0KSB7XG4gICAgICBjb25zb2xlLmxvZyh0YXNrKTtcbiAgICAgIGNvbnNvbGUubG9nKGZvcm1hdFRhc2tOYW1lKHRhc2spKTtcbiAgICAgIGlmIChmb3JtYXRUYXNrTmFtZSh0YXNrKSA9PT0gZXZlbnRJbWFnZURpZ2VzdCkge1xuICAgICAgICB2dWxuZXJhYmxlVGFza0xpc3QucHVzaCh0YXNrKTtcbiAgICAgIH1cbiAgICB9XG4gICAgY29uc29sZS5sb2codnVsbmVyYWJsZVRhc2tMaXN0KTtcbiAgICByZXR1cm4gdnVsbmVyYWJsZVRhc2tMaXN0O1xuICB9XG4gIHJldHVybiB1bmRlZmluZWQ7XG59O1xuXG5jb25zdCBjb21wYXJlRGlnZXN0cyA9IChcbiAgZXZlbnRJbWFnZURpZ2VzdDogc3RyaW5nLFxuICBpbWFnZURpZ2VzdDogc3RyaW5nXG4pOiBib29sZWFuID0+IHtcbiAgcmV0dXJuIGV2ZW50SW1hZ2VEaWdlc3QgPT09IGltYWdlRGlnZXN0O1xufTtcblxuLy8gdGFrZXMgbGlzdCBvZiB2dWxuZXJhYmxlIHRhc2sgQVJOIGFuZCBldmVudGltYWdlZGlnZXN0XG4vLyBwcmludHMgdGhlIGNvbnRhaW5lciBuYW1lIGFsb25nIHdpdGggdGhlIHRhc2sgQVJOXG4vLyBjb25zdCBwcmludExvZ01lc3NhZ2UgPSBhc3luYyAoXG4vLyAgIGxpc3RPZlZ1bG5lcmFibGVUYXNrczogc3RyaW5nW10gfCB1bmRlZmluZWQsXG4vLyAgIGV2ZW50SW1nRGlnZXN0OiBzdHJpbmdcbi8vICkgPT4ge1xuLy8gICBpZiAobGlzdE9mVnVsbmVyYWJsZVRhc2tzID09IHVuZGVmaW5lZCkge1xuLy8gICAgIGNvbnNvbGUubG9nKFwiVnVsbmVyYWJsZSB0YXNrIGxpc3QgaXMgdW5kZWZpbmVkLlwiKTtcbi8vICAgfSBlbHNlIGlmIChsaXN0T2ZWdWxuZXJhYmxlVGFza3MubGVuZ3RoID09PSAwKSB7XG4vLyAgICAgY29uc29sZS5sb2coYE5vIEVDUyB0YXNrcyB3aXRoIHZ1bG5lcmFibGUgaW1hZ2UgJHtldmVudEltZ0RpZ2VzdH0gZm91bmQuYCk7XG4vLyAgIH0gZWxzZSB7XG4vLyAgICAgLy8gZm9yIChjb25zdCB2dWxuRGlnZXN0IG9mIGxpc3RPZlZ1bG5lcmFibGVUYXNrcykge1xuLy8gICAgIC8vICAgaWYgKGNvbXBhcmVEaWdlc3RzKHZ1bG5EaWdlc3QsIGV2ZW50SW1nRGlnZXN0KSkge1xuLy8gICAgIC8vICAgICBjb25zb2xlLmxvZyhcbi8vICAgICAvLyAgICAgICBgRUNTIHRhc2sgd2l0aCB2dWxuZXJhYmxlIGltYWdlICR7ZXZlbnRJbWdEaWdlc3R9IGZvdW5kOiAke3Z1bG5EaWdlc3R9YFxuLy8gICAgIC8vICAgICApO1xuLy8gICAgIC8vICAgICBjb25zb2xlLmxvZyhgJHt2dWxuRGlnZXN0fWApO1xuLy8gICAgIC8vICAgICAvLyBwcmludCB0aGUgZW50aXJlIHRhc2sgZGVzY3JpcHRpb25cbi8vICAgICAvLyAgIH1cbi8vICAgICAvLyB9XG4vLyAgICAgY29uc3QgaW5wdXQgPSB7XG4vLyAgICAgICB0YXNrczogbGlzdE9mVnVsbmVyYWJsZVRhc2tzLFxuLy8gICAgIH07XG4vLyAgICAgY29uc3QgY29tbWFuZCA9IG5ldyBEZXNjcmliZVRhc2tzQ29tbWFuZChpbnB1dCk7XG4vLyAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBlY3Muc2VuZChjb21tYW5kKTtcbi8vICAgICBmb3IgKGNvbnN0IHRhc2sgb2YgcmVzcG9uc2UudGFza3MhKSB7XG4vLyAgICAgICBmb3IgKGNvbnN0IGNvbnRhaW5lciBvZiB0YXNrLmNvbnRhaW5lcnMhKSB7XG4vLyAgICAgICAgIC8vIHByaW50IHRoZSB0YXNrIEFSTlxuLy8gICAgICAgICBjb25zb2xlLmxvZyhgQ29udGFpbmVyICR7Y29udGFpbmVyLm5hbWV9IGZvdW5kIHdpdGhcbi8vICAgICAgICAgICAgICAgICAgdnVsbmVyYWJsZSBpbWFnZSAke2V2ZW50SW1nRGlnZXN0fS4gUmVmZXIgdG8gdGFzayBBUk4gJHt0YXNrLnRhc2tBcm59YCk7XG4vLyAgICAgICAgIC8vIHByaW50IHRoZSBlbnRpcmUgY29udGFpbmVyIGluZm9ybWF0aW9uXG4vLyAgICAgICAgIGNvbnNvbGUubG9nKGNvbnRhaW5lcik7XG4vLyAgICAgICB9XG4vLyAgICAgfVxuLy8gICB9XG4vLyB9O1xuXG5leHBvcnQgY29uc3QgaGFuZGxlciA9IGFzeW5jIGZ1bmN0aW9uIChcbiAgZXZlbnQ6IEV2ZW50QnJpZGdlRXZlbnQ8c3RyaW5nLCBhbnk+LFxuICBjb250ZXh0OiBDb250ZXh0LFxuICBjYWxsYmFjazogQ2FsbGJhY2tcbikge1xuICAvLyBjb25zb2xlLmxvZyhgXG4gIC8vICMjIyMjIyMjIyMjIyMjI1xuICAvLyAke0pTT04uc3RyaW5naWZ5KGV2ZW50KX1cbiAgLy8gIyMjIyMjIyMjIyMjIyMjXG4gIC8vIGApXG4gIGNvbnN0IGV2ZW50SW1hZ2VBUk46IHN0cmluZyA9IGV2ZW50LnJlc291cmNlc1swXTtcbiAgLy8gY29uc3QgZXZlbnRJbWFnZURpZ2VzdDogc3RyaW5nID0gZXZlbnQuZGV0YWlsLnJlc291cmNlcy5hd3NFY3JDb250YWluZXJJbWFnZS5pbWFnZUhhc2hcbiAgY29uc3QgZXZlbnRJbWFnZUFSTkRpZ2VzdEluZGV4ID0gZXZlbnRJbWFnZUFSTi5sYXN0SW5kZXhPZihcIi9zaGEyNTY6XCIpO1xuICBjb25zdCBldmVudEltYWdlRGlnZXN0ID0gZXZlbnRJbWFnZUFSTi5zbGljZShldmVudEltYWdlQVJORGlnZXN0SW5kZXggKyAxKTsgLy8gYWRkZWQgKyAxIHRvIHJlbW92ZSB0aGUgLyBpbiB0aGUgc3RyaW5nXG4gIC8vIGNvbnNvbGUubG9nKGBcbiAgLy8gIyMjIyMjIyMjIyMjIyMjXG4gIC8vIFRoaXMgaXMgdGhlIGV2ZW50IGltYWdlIGRpZ2VzdDogJHtldmVudEltYWdlRGlnZXN0fVxuICAvLyAjIyMjIyMjIyMjIyMjIyNcbiAgLy8gYCk7XG5cbiAgY29uc3QgY2x1c3Rlckxpc3QgPSBhd2FpdCBnZXRMaXN0T2ZDbHVzdGVyQVJOKCk7IC8vIGdldCBsaXN0IG9mIGNsdXN0ZXJzXG4gIGxldCBhbGxUYXNrcyA6IFRhc2tbXSA7IC8vIGVtcHR5IGxpc3QgdG8gaG9sZCBhbGwgdGFzayBkZXNjcmlwdGlvbnNcbiAgZm9yIChjb25zdCBjbHVzdGVyIG9mIGNsdXN0ZXJMaXN0KSB7XG4gICAgY29uc3QgdGFza0lkcyA9IGF3YWl0IGxpc3RUYXNrc0Zyb21DbHVzdGVyQVJOKGNsdXN0ZXIpOyAvLyBnZXR0aW5nIGFsbCB0YXNrIGlkcyBwZXIgY2x1c3RlclxuICAgIGlmICh0YXNrSWRzICE9IHVuZGVmaW5lZCkge1xuICAgICAgY29uc3QgdGFza0Rlc2NyaXB0aW9ucyA9IGF3YWl0IGdldFRhc2tEZXNjcmlwdGlvbnMoY2x1c3RlciwgdGFza0lkcyk7IC8vIGdldHRpbmcgYWxsIHRhc2sgZGVzY3JpcHRpb25zIHBlciBjbHVzdGVyXG4gICAgICBhbGxUYXNrcyA9IGFsbFRhc2tzIS5jb25jYXQodGFza0Rlc2NyaXB0aW9ucyEpO1xuICAgIH1cbiAgfVxuICBmb3IgKGNvbnN0IHRhc2sgb2YgYWxsVGFza3MhKSB7IFxuICAgIGlmICh0YXNrLmNvbnRhaW5lcnMpeyBcbiAgICAgIGZvciAoY29uc3QgY29udGFpbmVyIG9mIHRhc2suY29udGFpbmVycyEpIHtcbiAgICAgICAgaWYgKGNvbXBhcmVEaWdlc3RzKGNvbnRhaW5lci5pbWFnZURpZ2VzdCEsIGV2ZW50SW1hZ2VEaWdlc3QpKSB7XG4gICAgICAgICAgY29uc29sZS5sb2coYCR7Y29udGFpbmVyLm5hbWV9IGhhcyBiZWVuIGZvdW5kIHRvIGhhdmUgYSBuZXcgdnVsbmVyYWJpbGl0eS4gVGhlIGFzc29jaWF0ZWQgaW1hZ2UgY2FuIGJlIGZvdW5kIGhlcmU6ICR7Y29udGFpbmVyLmltYWdlfX1gKVxuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuICB9XG59O1xuIl19