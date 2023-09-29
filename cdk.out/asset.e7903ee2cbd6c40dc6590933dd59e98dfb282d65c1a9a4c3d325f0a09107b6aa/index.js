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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyJpbmRleC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFDQSxvREFPNkI7QUFHN0IsTUFBTSxHQUFHLEdBQUcsSUFBSSxzQkFBUyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0FBRTlCLDhCQUE4QjtBQUM5QixNQUFNLG1CQUFtQixHQUFHLEtBQUssSUFBdUIsRUFBRTtJQUN4RCxJQUFJLFdBQVcsR0FBYSxFQUFFLENBQUM7SUFDL0IsSUFBSSxTQUE2QixDQUFDO0lBRWxDLE1BQU0sS0FBSyxHQUFHLEVBQUUsQ0FBQztJQUNqQixNQUFNLE9BQU8sR0FBRyxJQUFJLGdDQUFtQixDQUFDLEtBQUssQ0FBQyxDQUFDO0lBQy9DLEdBQUc7UUFDRCxNQUFNLFFBQVEsR0FBRyxNQUFNLEdBQUcsQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUM7UUFDekMsZ0JBQWdCO1FBQ2hCLG9CQUFvQjtRQUNwQixxREFBcUQ7UUFDckQsb0JBQW9CO1FBQ3BCLEtBQUs7UUFDTCxJQUFJLFFBQVEsSUFBSSxTQUFTLEVBQUU7WUFDekIsZ0NBQWdDO1lBQ2hDLHNCQUFzQjtZQUN0QixTQUFTLEdBQUcsUUFBUSxDQUFDLFNBQVMsQ0FBQztZQUMvQixXQUFXLEdBQUcsV0FBVyxDQUFDLE1BQU0sQ0FBQyxRQUFRLENBQUMsV0FBWSxDQUFDLENBQUM7U0FDekQ7S0FDRixRQUFRLFNBQVMsRUFBRTtJQUNwQixPQUFPLFdBQVcsQ0FBQztBQUNyQixDQUFDLENBQUM7QUFFRixzREFBc0Q7QUFDdEQsTUFBTSx1QkFBdUIsR0FBRyxLQUFLLEVBQUUsV0FBbUIsRUFBRSxFQUFFO0lBQzVELElBQUksUUFBUSxHQUFhLEVBQUUsQ0FBQztJQUM1QixJQUFJLFNBQTZCLENBQUM7SUFFbEMsR0FBRztRQUNELE1BQU0sS0FBSyxHQUFHO1lBQ1osT0FBTyxFQUFFLFdBQVc7U0FDckIsQ0FBQztRQUNGLE1BQU0sT0FBTyxHQUFHLElBQUks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LElBQUksd0ZBQXdGLFNBQVMsQ0FBQyxLQUFLLEdBQUcsQ0FBQyxDQUFBO2lCQUN6STthQUNGO1NBQ0Y7S0FDRjtBQUNILENBQUMsQ0FBQztBQXRDVyxRQUFBLE9BQU8sV0FzQ2xCIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgQ2FsbGJhY2ssIEV2ZW50QnJpZGdlRXZlbnQsIENvbnRleHQgfSBmcm9tIFwiYXdzLWxhbWJkYVwiO1xuaW1wb3J0IHtcbiAgRUNTQ2xpZW50LFxuICBMaXN0Q2x1c3RlcnNDb21tYW5kLFxuICBMaXN0VGFza3NDb21tYW5kLFxuICBEZXNjcmliZVRhc2tzQ29tbWFuZCxcbiAgRGVzY3JpYmVDbHVzdGVyc0NvbW1hbmQsXG4gIFRhc2tcbn0gZnJvbSBcIkBhd3Mtc2RrL2NsaWVudC1lY3NcIjtcbmltcG9ydCB7IFRhc2tEZWZpbml0aW9uIH0gZnJvbSBcImF3cy1jZGstbGliL2F3cy1lY3NcIjtcblxuY29uc3QgZWNzID0gbmV3IEVDU0NsaWVudCh7fSk7XG5cbi8vIHJldHVybnMgbGlzdCBvZiBjbHVzdGVyIEFSTlxuY29uc3QgZ2V0TGlzdE9mQ2x1c3RlckFSTiA9IGFzeW5jICgpOiBQcm9taXNlPHN0cmluZ1tdPiA9PiB7XG4gIGxldCBjbHVzdGVyTGlzdDogc3RyaW5nW10gPSBbXTtcbiAgbGV0IG5leHRUb2tlbjogc3RyaW5nIHwgdW5kZWZpbmVkO1xuXG4gIGNvbnN0IGlucHV0ID0ge307XG4gIGNvbnN0IGNvbW1hbmQgPSBuZXcgTGlzdENsdXN0ZXJzQ29tbWFuZChpbnB1dCk7XG4gIGRvIHtcbiAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGVjcy5zZW5kKGNvbW1hbmQpO1xuICAgIC8vIGNvbnNvbGUubG9nKGBcbiAgICAvLyAgICAgIyMjIyMjIyMjIyMjI1xuICAgIC8vICAgICBsaXN0IG9mIGNsdXN0ZXJzOiAgJHtKU09OLnN0cmluZ2lmeShyZXNwb25zZSl9XG4gICAgLy8gICAgICMjIyMjIyMjIyMjIyNcbiAgICAvLyBgKVxuICAgIGlmIChyZXNwb25zZSAhPSB1bmRlZmluZWQpIHtcbiAgICAgIC8vIHJldHVybiByZXNwb25zZS5jbHVzdGVyQXJucyE7XG4gICAgICAvLyBzZXQgbmV4dCB0b2tlbiBoZXJlXG4gICAgICBuZXh0VG9rZW4gPSByZXNwb25zZS5uZXh0VG9rZW47XG4gICAgICBjbHVzdGVyTGlzdCA9IGNsdXN0ZXJMaXN0LmNvbmNhdChyZXNwb25zZS5jbHVzdGVyQXJucyEpO1xuICAgIH1cbiAgfSB3aGlsZSAobmV4dFRva2VuKTtcbiAgcmV0dXJuIGNsdXN0ZXJMaXN0O1xufTtcblxuLy8gcmV0dXJucyBsaXN0IG9mIEFMTCB0YXNrIEFSTiBmcm9tIHNwZWNpZmllZCBjbHVzdGVyXG5jb25zdCBsaXN0VGFza3NGcm9tQ2x1c3RlckFSTiA9IGFzeW5jIChjbHVzdGVyTmFtZTogc3RyaW5nKSA9PiB7XG4gIGxldCB0YXNrTGlzdDogc3RyaW5nW10gPSBbXTtcbiAgbGV0IG5leHRUb2tlbjogc3RyaW5nIHwgdW5kZWZpbmVkO1xuXG4gIGRvIHtcbiAgICBjb25zdCBpbnB1dCA9IHtcbiAgICAgIGNsdXN0ZXI6IGNsdXN0ZXJOYW1lLFxuICAgIH07XG4gICAgY29uc3QgY29tbWFuZCA9IG5ldyBMaXN0VGFza3NDb21tYW5kKGlucHV0KTtcbiAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGVjcy5zZW5kKGNvbW1hbmQpO1xuICAgIC8vIGNvbnNvbGUubG9nKGBcbiAgICAvLyAgICMjIyMjIyMjIyMjIyNcbiAgICAvLyAgIGxpc3QgdGFza3MgZnJvbSBjbHVzdGVyIGFybjogJHtyZXNwb25zZS50YXNrQXJuc31cbiAgICAvLyAgICMjIyMjIyMjIyMjIyNcbiAgICAvLyAgIGApO1xuICAgIC8vIHJldHVybiByZXNwb25zZS50YXNrQXJucztcbiAgICBpZiAocmVzcG9uc2UgIT0gdW5kZWZpbmVkKSB7XG4gICAgICBuZXh0VG9rZW4gPSByZXNwb25zZS5uZXh0VG9rZW47XG4gICAgICBpZiAocmVzcG9uc2UudGFza0FybnMgIT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRhc2tMaXN0ID0gdGFza0xpc3QuY29uY2F0KHJlc3BvbnNlLnRhc2tBcm5zKTtcbiAgICAgIH1cbiAgICB9XG4gIH0gd2hpbGUgKG5leHRUb2tlbik7XG4gIHJldHVybiB0YXNrTGlzdDtcbn07XG5cbi8vIGZvcm1hdHMgdGFzayBBUk4gdG8gSURcbmNvbnN0IGZvcm1hdFRhc2tOYW1lID0gKHRhc2tBUk46IHN0cmluZyk6IHN0cmluZyA9PiB7XG4gIGNvbnN0IGluZGV4T2ZMYXN0U2xhc2ggPSB0YXNrQVJOLmxhc3RJbmRleE9mKFwiL1wiKTtcbiAgY29uc3QgdGFza05hbWUgPSB0YXNrQVJOLnN1YnN0cmluZyhpbmRleE9mTGFzdFNsYXNoICsgMSk7XG4gIHJldHVybiB0YXNrTmFtZTtcbn07XG5cbmNvbnN0IGdldFRhc2tEZXNjcmlwdGlvbnMgPSBhc3luYyAoY2x1c3RlckFSTjpzdHJpbmcsIHRhc2tJZExpc3Q6IHN0cmluZ1tdKTogUHJvbWlzZTxUYXNrW10gfCB1bmRlZmluZWQ+ID0+IHtcbiAgY29uc3QgaW5wdXQgPSB7XG4gICAgdGFza3M6IHRhc2tJZExpc3QsXG4gICAgY2x1c3RlcjogY2x1c3RlckFSTlxuICB9XG4gIGNvbnN0IGNvbW1hbmQgPSBuZXcgRGVzY3JpYmVUYXNrc0NvbW1hbmQoaW5wdXQpO1xuICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGVjcy5zZW5kKGNvbW1hbmQpO1xuICBpZiAocmVzcG9uc2UgIT0gdW5kZWZpbmVkKSB7XG4gICAgcmV0dXJuIHJlc3BvbnNlLnRhc2tzO1xuICB9XG4gIHJldHVybiB1bmRlZmluZWQ7XG59XG5cbmNvbnN0IGdldFZ1bG5lcmFibGVEaWdlc3RzUGVyQVJOID0gYXN5bmMgKGNsdXN0ZXJBUk46IHN0cmluZyk6IFByb21pc2U8YW55PiA9PiB7XG4gIGNvbnN0IHRhc2tMaXN0ID0gYXdhaXQgbGlzdFRhc2tzRnJvbUNsdXN0ZXJBUk4oY2x1c3RlckFSTik7XG4gIGxldCB2dWxuZXJhYmxlRGlnZXN0czogeyBba2V5OiBzdHJpbmddOiBzdHJpbmdbXSB9ID0ge307XG4gIGlmICh0YXNrTGlzdCAhPSB1bmRlZmluZWQpIHtcbiAgICBjb25zdCB0YXNrSWRMaXN0ID0gdGFza0xpc3QubWFwKCh0YXNrOiBzdHJpbmcpID0+IGZvcm1hdFRhc2tOYW1lKHRhc2spKTtcbiAgICBjb25zdCBpbnB1dCA9IHtcbiAgICAgIHRhc2tzOiB0YXNrSWRMaXN0LFxuICAgICAgY2x1c3RlcjogY2x1c3RlckFSTixcbiAgICB9O1xuICAgIGNvbnN0IGNvbW1hbmQgPSBuZXcgRGVzY3JpYmVUYXNrc0NvbW1hbmQoaW5wdXQpO1xuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4gICAgY29uc3QgbGlzdE9mVGFza3NGcm9tUmVzcG9uc2UgPSByZXNwb25zZS50YXNrcztcbiAgICBpZiAobGlzdE9mVGFza3NGcm9tUmVzcG9uc2UgIT0gdW5kZWZpbmVkKSB7XG4gICAgICBmb3IgKGNvbnN0IHRhc2sgb2YgbGlzdE9mVGFza3NGcm9tUmVzcG9uc2UpIHtcbiAgICAgICAgZm9yIChsZXQgbiA9IDA7IG4gPCB0YXNrLmNvbnRhaW5lcnMhLmxlbmd0aDsgbisrKSB7XG4gICAgICAgICAgaWYgKHRhc2suY29udGFpbmVycyFbbl0udGFza0FybiEgaW4gdnVsbmVyYWJsZURpZ2VzdHMpIHtcbiAgICAgICAgICAgIHZ1bG5lcmFibGVEaWdlc3RzW3Rhc2suY29udGFpbmVycyFbbl0udGFza0FybiFdLnB1c2goXG4gICAgICAgICAgICAgIHRhc2suY29udGFpbmVycyFbbl0uaW1hZ2VEaWdlc3QhXG4gICAgICAgICAgICApO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB2dWxuZXJhYmxlRGlnZXN0c1t0YXNrLmNvbnRhaW5lcnMhW25dLnRhc2tBcm4hXSA9IFtcbiAgICAgICAgICAgICAgdGFzay5jb250YWluZXJzIVtuXS5pbWFnZURpZ2VzdCEsXG4gICAgICAgICAgICBdO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gdnVsbmVyYWJsZURpZ2VzdHM7XG4gIH1cbiAgcmV0dXJuIHVuZGVmaW5lZDtcbn07XG5cbi8vIHJldHVybnMgdGhlIG5hbWUgb2YgdGhlIGNsdXN0ZXIgb3IgdW5kZWZpbmVkIGlmIG5vdCBmb3VuZFxuY29uc3QgZ2V0Q2x1c3Rlck5hbWUgPSBhc3luYyAoXG4gIGNsdXN0ZXJBUk46IHN0cmluZ1xuKTogUHJvbWlzZTxzdHJpbmcgfCB1bmRlZmluZWQ+ID0+IHtcbiAgY29uc3QgaW5wdXQgPSB7XG4gICAgY2x1c3RlcnM6IFtjbHVzdGVyQVJOXSxcbiAgfTtcbiAgY29uc3QgY29tbWFuZCA9IG5ldyBEZXNjcmliZUNsdXN0ZXJzQ29tbWFuZChpbnB1dCk7XG4gIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4gIGlmIChyZXNwb25zZSAhPSB1bmRlZmluZWQpIHtcbiAgICByZXR1cm4gcmVzcG9uc2UuY2x1c3RlcnMhWzBdLmNsdXN0ZXJOYW1lITtcbiAgfVxuICByZXR1cm4gdW5kZWZpbmVkO1xufTtcblxuLy8gZmlsdGVycyBsaXN0IG9mIHRhc2tzIHRvIGp1c3QgdnVsbmVyYWJsZSB0YXNrc1xuLy8gdHJ5IHdpdGgganVzdCByZXR1cm5pbmcgYSB0YXNrbGlzdFxuY29uc3QgZ2V0VnVsbmVyYWJsZVRhc2tMaXN0ID0gYXN5bmMgKFxuICBldmVudEltYWdlRGlnZXN0OiBzdHJpbmcsXG4gIGNsdXN0ZXJBUk46IHN0cmluZ1xuKTogUHJvbWlzZTxzdHJpbmdbXSB8IHVuZGVmaW5lZD4gPT4ge1xuICBjb25zdCB2dWxuZXJhYmxlVGFza0xpc3Q6IHN0cmluZ1tdID0gW107XG4gIGNvbnN0IGNsdXN0ZXJOYW1lID0gYXdhaXQgZ2V0Q2x1c3Rlck5hbWUoY2x1c3RlckFSTik7XG4gIGNvbnN0IHRhc2tMaXN0ID0gYXdhaXQgbGlzdFRhc2tzRnJvbUNsdXN0ZXJBUk4oY2x1c3RlckFSTik7XG4gIGNvbnNvbGUubG9nKGBUaGUgbGlzdCBvZiB0YXNrczogJHt0YXNrTGlzdC5tYXAoKHRhc2spPT5mb3JtYXRUYXNrTmFtZSh0YXNrKSl9YClcbiAgY29uc3QgZm9ybWF0dGVkVGFza3MgPSB0YXNrTGlzdC5tYXAoKHRhc2spPT5mb3JtYXRUYXNrTmFtZSh0YXNrKSk7XG4gIGNvbnN0IGlucHV0ID0ge1xuICAgIHRhc2tzOiBmb3JtYXR0ZWRUYXNrcyxcbiAgfTtcbiAgY29uc3QgY29tbWFuZCA9IG5ldyBEZXNjcmliZVRhc2tzQ29tbWFuZChpbnB1dCk7XG4gIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4gIGNvbnNvbGUubG9nKHJlc3BvbnNlKTtcbiAgaWYgKHRhc2tMaXN0ID09PSB1bmRlZmluZWQpIHtcbiAgICBjb25zb2xlLmxvZyhgTm8gRUNTIHRhc2tzIGZvdW5kIGluIGNsdXN0ZXIgJHtjbHVzdGVyTmFtZX1gKTtcbiAgfSBlbHNlIHtcbiAgICBmb3IgKGNvbnN0IHRhc2sgb2YgdGFza0xpc3QpIHtcbiAgICAgIGNvbnNvbGUubG9nKHRhc2spO1xuICAgICAgY29uc29sZS5sb2coZm9ybWF0VGFza05hbWUodGFzaykpO1xuICAgICAgaWYgKGZvcm1hdFRhc2tOYW1lKHRhc2spID09PSBldmVudEltYWdlRGlnZXN0KSB7XG4gICAgICAgIHZ1bG5lcmFibGVUYXNrTGlzdC5wdXNoKHRhc2spO1xuICAgICAgfVxuICAgIH1cbiAgICBjb25zb2xlLmxvZyh2dWxuZXJhYmxlVGFza0xpc3QpO1xuICAgIHJldHVybiB2dWxuZXJhYmxlVGFza0xpc3Q7XG4gIH1cbiAgcmV0dXJuIHVuZGVmaW5lZDtcbn07XG5cbmNvbnN0IGNvbXBhcmVEaWdlc3RzID0gKFxuICBldmVudEltYWdlRGlnZXN0OiBzdHJpbmcsXG4gIGltYWdlRGlnZXN0OiBzdHJpbmdcbik6IGJvb2xlYW4gPT4ge1xuICByZXR1cm4gZXZlbnRJbWFnZURpZ2VzdCA9PT0gaW1hZ2VEaWdlc3Q7XG59O1xuXG4vLyB0YWtlcyBsaXN0IG9mIHZ1bG5lcmFibGUgdGFzayBBUk4gYW5kIGV2ZW50aW1hZ2VkaWdlc3Rcbi8vIHByaW50cyB0aGUgY29udGFpbmVyIG5hbWUgYWxvbmcgd2l0aCB0aGUgdGFzayBBUk5cbmNvbnN0IHByaW50TG9nTWVzc2FnZSA9IGFzeW5jIChcbiAgbGlzdE9mVnVsbmVyYWJsZVRhc2tzOiBzdHJpbmdbXSB8IHVuZGVmaW5lZCxcbiAgZXZlbnRJbWdEaWdlc3Q6IHN0cmluZ1xuKSA9PiB7XG4gIGlmIChsaXN0T2ZWdWxuZXJhYmxlVGFza3MgPT0gdW5kZWZpbmVkKSB7XG4gICAgY29uc29sZS5sb2coXCJWdWxuZXJhYmxlIHRhc2sgbGlzdCBpcyB1bmRlZmluZWQuXCIpO1xuICB9IGVsc2UgaWYgKGxpc3RPZlZ1bG5lcmFibGVUYXNrcy5sZW5ndGggPT09IDApIHtcbiAgICBjb25zb2xlLmxvZyhgTm8gRUNTIHRhc2tzIHdpdGggdnVsbmVyYWJsZSBpbWFnZSAke2V2ZW50SW1nRGlnZXN0fSBmb3VuZC5gKTtcbiAgfSBlbHNlIHtcbiAgICAvLyBmb3IgKGNvbnN0IHZ1bG5EaWdlc3Qgb2YgbGlzdE9mVnVsbmVyYWJsZVRhc2tzKSB7XG4gICAgLy8gICBpZiAoY29tcGFyZURpZ2VzdHModnVsbkRpZ2VzdCwgZXZlbnRJbWdEaWdlc3QpKSB7XG4gICAgLy8gICAgIGNvbnNvbGUubG9nKFxuICAgIC8vICAgICAgIGBFQ1MgdGFzayB3aXRoIHZ1bG5lcmFibGUgaW1hZ2UgJHtldmVudEltZ0RpZ2VzdH0gZm91bmQ6ICR7dnVsbkRpZ2VzdH1gXG4gICAgLy8gICAgICk7XG4gICAgLy8gICAgIGNvbnNvbGUubG9nKGAke3Z1bG5EaWdlc3R9YCk7XG4gICAgLy8gICAgIC8vIHByaW50IHRoZSBlbnRpcmUgdGFzayBkZXNjcmlwdGlvblxuICAgIC8vICAgfVxuICAgIC8vIH1cbiAgICBjb25zdCBpbnB1dCA9IHtcbiAgICAgIHRhc2tzOiBsaXN0T2ZWdWxuZXJhYmxlVGFza3MsXG4gICAgfTtcbiAgICBjb25zdCBjb21tYW5kID0gbmV3IERlc2NyaWJlVGFza3NDb21tYW5kKGlucHV0KTtcbiAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGVjcy5zZW5kKGNvbW1hbmQpO1xuICAgIGZvciAoY29uc3QgdGFzayBvZiByZXNwb25zZS50YXNrcyEpIHtcbiAgICAgIGZvciAoY29uc3QgY29udGFpbmVyIG9mIHRhc2suY29udGFpbmVycyEpIHtcbiAgICAgICAgLy8gcHJpbnQgdGhlIHRhc2sgQVJOXG4gICAgICAgIGNvbnNvbGUubG9nKGBDb250YWluZXIgJHtjb250YWluZXIubmFtZX0gZm91bmQgd2l0aFxuICAgICAgICAgICAgICAgICB2dWxuZXJhYmxlIGltYWdlICR7ZXZlbnRJbWdEaWdlc3R9LiBSZWZlciB0byB0YXNrIEFSTiAke3Rhc2sudGFza0Fybn1gKTtcbiAgICAgICAgLy8gcHJpbnQgdGhlIGVudGlyZSBjb250YWluZXIgaW5mb3JtYXRpb25cbiAgICAgICAgY29uc29sZS5sb2coY29udGFpbmVyKTtcbiAgICAgIH1cbiAgICB9XG4gIH1cbn07XG5cbmV4cG9ydCBjb25zdCBoYW5kbGVyID0gYXN5bmMgZnVuY3Rpb24gKFxuICBldmVudDogRXZlbnRCcmlkZ2VFdmVudDxzdHJpbmcsIGFueT4sXG4gIGNvbnRleHQ6IENvbnRleHQsXG4gIGNhbGxiYWNrOiBDYWxsYmFja1xuKSB7XG4gIC8vIGNvbnNvbGUubG9nKGBcbiAgLy8gIyMjIyMjIyMjIyMjIyMjXG4gIC8vICR7SlNPTi5zdHJpbmdpZnkoZXZlbnQpfVxuICAvLyAjIyMjIyMjIyMjIyMjIyNcbiAgLy8gYClcbiAgY29uc3QgZXZlbnRJbWFnZUFSTjogc3RyaW5nID0gZXZlbnQucmVzb3VyY2VzWzBdO1xuICAvLyBjb25zdCBldmVudEltYWdlRGlnZXN0OiBzdHJpbmcgPSBldmVudC5kZXRhaWwucmVzb3VyY2VzLmF3c0VjckNvbnRhaW5lckltYWdlLmltYWdlSGFzaFxuICBjb25zdCBldmVudEltYWdlQVJORGlnZXN0SW5kZXggPSBldmVudEltYWdlQVJOLmxhc3RJbmRleE9mKFwiL3NoYTI1NjpcIik7XG4gIGNvbnN0IGV2ZW50SW1hZ2VEaWdlc3QgPSBldmVudEltYWdlQVJOLnNsaWNlKGV2ZW50SW1hZ2VBUk5EaWdlc3RJbmRleCArIDEpOyAvLyBhZGRlZCArIDEgdG8gcmVtb3ZlIHRoZSAvIGluIHRoZSBzdHJpbmdcbiAgLy8gY29uc29sZS5sb2coYFxuICAvLyAjIyMjIyMjIyMjIyMjIyNcbiAgLy8gVGhpcyBpcyB0aGUgZXZlbnQgaW1hZ2UgZGlnZXN0OiAke2V2ZW50SW1hZ2VEaWdlc3R9XG4gIC8vICMjIyMjIyMjIyMjIyMjI1xuICAvLyBgKTtcblxuICBjb25zdCBjbHVzdGVyTGlzdCA9IGF3YWl0IGdldExpc3RPZkNsdXN0ZXJBUk4oKTsgLy8gZ2V0IGxpc3Qgb2YgY2x1c3RlcnNcbiAgbGV0IGFsbFRhc2tzIDogVGFza1tdIDsgLy8gZW1wdHkgbGlzdCB0byBob2xkIGFsbCB0YXNrIGRlc2NyaXB0aW9uc1xuICBmb3IgKGNvbnN0IGNsdXN0ZXIgb2YgY2x1c3Rlckxpc3QpIHtcbiAgICBjb25zdCB0YXNrSWRzID0gYXdhaXQgbGlzdFRhc2tzRnJvbUNsdXN0ZXJBUk4oY2x1c3Rlcik7IC8vIGdldHRpbmcgYWxsIHRhc2sgaWRzIHBlciBjbHVzdGVyXG4gICAgaWYgKHRhc2tJZHMgIT0gdW5kZWZpbmVkKSB7XG4gICAgICBjb25zdCB0YXNrRGVzY3JpcHRpb25zID0gYXdhaXQgZ2V0VGFza0Rlc2NyaXB0aW9ucyhjbHVzdGVyLCB0YXNrSWRzKTsgLy8gZ2V0dGluZyBhbGwgdGFzayBkZXNjcmlwdGlvbnMgcGVyIGNsdXN0ZXJcbiAgICAgIGFsbFRhc2tzID0gYWxsVGFza3MhLmNvbmNhdCh0YXNrRGVzY3JpcHRpb25zISk7XG4gICAgfVxuICB9XG4gIGZvciAoY29uc3QgdGFzayBvZiBhbGxUYXNrcyEpIHsgXG4gICAgaWYgKHRhc2suY29udGFpbmVycyl7IFxuICAgICAgZm9yIChjb25zdCBjb250YWluZXIgb2YgdGFzay5jb250YWluZXJzISkge1xuICAgICAgICBpZiAoY29tcGFyZURpZ2VzdHMoY29udGFpbmVyLmltYWdlRGlnZXN0ISwgZXZlbnRJbWFnZURpZ2VzdCkpIHtcbiAgICAgICAgICBjb25zb2xlLmxvZyhgJHtjb250YWluZXIubmFtZX0gaGFzIGJlZW4gZm91bmQgdG8gaGF2ZSBhIG5ldyB2dWxuZXJhYmlsaXR5LiBUaGUgYXNzb2NpYXRlZCBpbWFnZSBjYW4gYmUgZm91bmQgaGVyZTogJHtjb250YWluZXIuaW1hZ2V9fWApXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG4gIH1cbn07XG4iXX0=