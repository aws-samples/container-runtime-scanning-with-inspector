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
        if (response != undefined) {
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
// const getVulnerableDigestsPerARN = async (clusterARN: string): Promise<any> => {
//   const taskList = await listTasksFromClusterARN(clusterARN);
//   let vulnerableDigests: { [key: string]: string[] } = {};
//   if (taskList != undefined) {
//     const taskIdList = taskList.map((task: string) => formatTaskName(task));
//     const input = {
//       tasks: taskIdList,
//       cluster: clusterARN,
//     };
//     const command = new DescribeTasksCommand(input);
//     const response = await ecs.send(command);
//     const listOfTasksFromResponse = response.tasks;
//     if (listOfTasksFromResponse != undefined) {
//       for (const task of listOfTasksFromResponse) {
//         for (let n = 0; n < task.containers!.length; n++) {
//           if (task.containers![n].taskArn! in vulnerableDigests) {
//             vulnerableDigests[task.containers![n].taskArn!].push(
//               task.containers![n].imageDigest!
//             );
//           } else {
//             vulnerableDigests[task.containers![n].taskArn!] = [
//               task.containers![n].imageDigest!,
//             ];
//           }
//         }
//       }
//     }
//     return vulnerableDigests;
//   }
//   return undefined;
// };
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
// const getVulnerableTaskList = async (
//   eventImageDigest: string,
//   clusterARN: string
// ): Promise<string[] | undefined> => {
//   const vulnerableTaskList: string[] = [];
//   const clusterName = await getClusterName(clusterARN);
//   const taskList = await listTasksFromClusterARN(clusterARN);
//   console.log(`The list of tasks: ${taskList.map((task)=>formatTaskName(task))}`)
//   const formattedTasks = taskList.map((task)=>formatTaskName(task));
//   const input = {
//     tasks: formattedTasks,
//   };
//   const command = new DescribeTasksCommand(input);
//   const response = await ecs.send(command);
//   console.log(response);
//   if (taskList === undefined) {
//     console.log(`No ECS tasks found in cluster ${clusterName}`);
//   } else {
//     for (const task of taskList) {
//       console.log(task);
//       console.log(formatTaskName(task));
//       if (formatTaskName(task) === eventImageDigest) {
//         vulnerableTaskList.push(task);
//       }
//     }
//     console.log(vulnerableTaskList);
//     return vulnerableTaskList;
//   }
//   return undefined;
// };
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
    const clusterList = await getListOfClusterARN(); // get list of clusters
    let allTasks; // empty list to hold all task descriptions
    for (const cluster of clusterList) {
        const taskIds = await listTasksFromClusterARN(cluster); // getting all task ids per cluster
        if (taskIds != undefined) {
            const taskDescriptions = await getTaskDescriptions(cluster, taskIds); // getting all task descriptions per cluster
            if (taskDescriptions != undefined) {
                allTasks = allTasks.concat(taskDescriptions);
            }
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyJpbmRleC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFDQSxvREFPNkI7QUFHN0IsTUFBTSxHQUFHLEdBQUcsSUFBSSxzQkFBUyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0FBRTlCLDhCQUE4QjtBQUM5QixNQUFNLG1CQUFtQixHQUFHLEtBQUssSUFBdUIsRUFBRTtJQUN4RCxJQUFJLFdBQVcsR0FBYSxFQUFFLENBQUM7SUFDL0IsSUFBSSxTQUE2QixDQUFDO0lBRWxDLE1BQU0sS0FBSyxHQUFHLEVBQUUsQ0FBQztJQUNqQixNQUFNLE9BQU8sR0FBRyxJQUFJLGdDQUFtQixDQUFDLEtBQUssQ0FBQyxDQUFDO0lBQy9DLEdBQUc7UUFDRCxNQUFNLFFBQVEsR0FBRyxNQUFNLEdBQUcsQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUM7UUFDekMsSUFBSSxRQUFRLElBQUksU0FBUyxFQUFFO1lBQ3pCLFNBQVMsR0FBRyxRQUFRLENBQUMsU0FBUyxDQUFDO1lBQy9CLFdBQVcsR0FBRyxXQUFXLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxXQUFZLENBQUMsQ0FBQztTQUN6RDtLQUNGLFFBQVEsU0FBUyxFQUFFO0lBQ3BCLE9BQU8sV0FBVyxDQUFDO0FBQ3JCLENBQUMsQ0FBQztBQUVGLHNEQUFzRDtBQUN0RCxNQUFNLHVCQUF1QixHQUFHLEtBQUssRUFBRSxXQUFtQixFQUFFLEVBQUU7SUFDNUQsSUFBSSxRQUFRLEdBQWEsRUFBRSxDQUFDO0lBQzVCLElBQUksU0FBNkIsQ0FBQztJQUVsQyxHQUFHO1FBQ0QsTUFBTSxLQUFLLEdBQUc7WUFDWixPQUFPLEVBQUUsV0FBVztTQUNyQixDQUFDO1FBQ0YsTUFBTSxPQUFPLEdBQUcsSUFBSSw2QkFBZ0IsQ0FBQyxLQUFLLENBQUMsQ0FBQztRQUM1QyxNQUFNLFFBQVEsR0FBRyxNQUFNLEdBQUcsQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUM7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dGV4dCB9IGZyb20gXCJhd3MtbGFtYmRhXCI7XG5pbXBvcnQge1xuICBFQ1NDbGllbnQsXG4gIExpc3RDbHVzdGVyc0NvbW1hbmQsXG4gIExpc3RUYXNrc0NvbW1hbmQsXG4gIERlc2NyaWJlVGFza3NDb21tYW5kLFxuICBEZXNjcmliZUNsdXN0ZXJzQ29tbWFuZCxcbiAgVGFza1xufSBmcm9tIFwiQGF3cy1zZGsvY2xpZW50LWVjc1wiO1xuaW1wb3J0IHsgVGFza0RlZmluaXRpb24gfSBmcm9tIFwiYXdzLWNkay1saWIvYXdzLWVjc1wiO1xuXG5jb25zdCBlY3MgPSBuZXcgRUNTQ2xpZW50KHt9KTtcblxuLy8gcmV0dXJucyBsaXN0IG9mIGNsdXN0ZXIgQVJOXG5jb25zdCBnZXRMaXN0T2ZDbHVzdGVyQVJOID0gYXN5bmMgKCk6IFByb21pc2U8c3RyaW5nW10+ID0+IHtcbiAgbGV0IGNsdXN0ZXJMaXN0OiBzdHJpbmdbXSA9IFtdO1xuICBsZXQgbmV4dFRva2VuOiBzdHJpbmcgfCB1bmRlZmluZWQ7XG5cbiAgY29uc3QgaW5wdXQgPSB7fTtcbiAgY29uc3QgY29tbWFuZCA9IG5ldyBMaXN0Q2x1c3RlcnNDb21tYW5kKGlucHV0KTtcbiAgZG8ge1xuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4gICAgaWYgKHJlc3BvbnNlICE9IHVuZGVmaW5lZCkge1xuICAgICAgbmV4dFRva2VuID0gcmVzcG9uc2UubmV4dFRva2VuO1xuICAgICAgY2x1c3Rlckxpc3QgPSBjbHVzdGVyTGlzdC5jb25jYXQocmVzcG9uc2UuY2x1c3RlckFybnMhKTtcbiAgICB9XG4gIH0gd2hpbGUgKG5leHRUb2tlbik7XG4gIHJldHVybiBjbHVzdGVyTGlzdDtcbn07XG5cbi8vIHJldHVybnMgbGlzdCBvZiBBTEwgdGFzayBBUk4gZnJvbSBzcGVjaWZpZWQgY2x1c3RlclxuY29uc3QgbGlzdFRhc2tzRnJvbUNsdXN0ZXJBUk4gPSBhc3luYyAoY2x1c3Rlck5hbWU6IHN0cmluZykgPT4ge1xuICBsZXQgdGFza0xpc3Q6IHN0cmluZ1tdID0gW107XG4gIGxldCBuZXh0VG9rZW46IHN0cmluZyB8IHVuZGVmaW5lZDtcblxuICBkbyB7XG4gICAgY29uc3QgaW5wdXQgPSB7XG4gICAgICBjbHVzdGVyOiBjbHVzdGVyTmFtZSxcbiAgICB9O1xuICAgIGNvbnN0IGNvbW1hbmQgPSBuZXcgTGlzdFRhc2tzQ29tbWFuZChpbnB1dCk7XG4gICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBlY3Muc2VuZChjb21tYW5kKTtcbiAgICBpZiAocmVzcG9uc2UgIT0gdW5kZWZpbmVkKSB7XG4gICAgICBuZXh0VG9rZW4gPSByZXNwb25zZS5uZXh0VG9rZW47XG4gICAgICBpZiAocmVzcG9uc2UudGFza0FybnMgIT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRhc2tMaXN0ID0gdGFza0xpc3QuY29uY2F0KHJlc3BvbnNlLnRhc2tBcm5zKTtcbiAgICAgIH1cbiAgICB9XG4gIH0gd2hpbGUgKG5leHRUb2tlbik7XG4gIHJldHVybiB0YXNrTGlzdDtcbn07XG5cbi8vIGZvcm1hdHMgdGFzayBBUk4gdG8gSURcbmNvbnN0IGZvcm1hdFRhc2tOYW1lID0gKHRhc2tBUk46IHN0cmluZyk6IHN0cmluZyA9PiB7XG4gIGNvbnN0IGluZGV4T2ZMYXN0U2xhc2ggPSB0YXNrQVJOLmxhc3RJbmRleE9mKFwiL1wiKTtcbiAgY29uc3QgdGFza05hbWUgPSB0YXNrQVJOLnN1YnN0cmluZyhpbmRleE9mTGFzdFNsYXNoICsgMSk7XG4gIHJldHVybiB0YXNrTmFtZTtcbn07XG5cbmNvbnN0IGdldFRhc2tEZXNjcmlwdGlvbnMgPSBhc3luYyAoY2x1c3RlckFSTjpzdHJpbmcsIHRhc2tJZExpc3Q6IHN0cmluZ1tdKTogUHJvbWlzZTxUYXNrW10gfCB1bmRlZmluZWQ+ID0+IHtcbiAgY29uc3QgaW5wdXQgPSB7XG4gICAgdGFza3M6IHRhc2tJZExpc3QsXG4gICAgY2x1c3RlcjogY2x1c3RlckFSTlxuICB9XG4gIGNvbnN0IGNvbW1hbmQgPSBuZXcgRGVzY3JpYmVUYXNrc0NvbW1hbmQoaW5wdXQpO1xuICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGVjcy5zZW5kKGNvbW1hbmQpO1xuICBpZiAocmVzcG9uc2UgIT0gdW5kZWZpbmVkKSB7XG4gICAgcmV0dXJuIHJlc3BvbnNlLnRhc2tzO1xuICB9XG4gIHJldHVybiB1bmRlZmluZWQ7XG59XG5cbi8vIGNvbnN0IGdldFZ1bG5lcmFibGVEaWdlc3RzUGVyQVJOID0gYXN5bmMgKGNsdXN0ZXJBUk46IHN0cmluZyk6IFByb21pc2U8YW55PiA9PiB7XG4vLyAgIGNvbnN0IHRhc2tMaXN0ID0gYXdhaXQgbGlzdFRhc2tzRnJvbUNsdXN0ZXJBUk4oY2x1c3RlckFSTik7XG4vLyAgIGxldCB2dWxuZXJhYmxlRGlnZXN0czogeyBba2V5OiBzdHJpbmddOiBzdHJpbmdbXSB9ID0ge307XG4vLyAgIGlmICh0YXNrTGlzdCAhPSB1bmRlZmluZWQpIHtcbi8vICAgICBjb25zdCB0YXNrSWRMaXN0ID0gdGFza0xpc3QubWFwKCh0YXNrOiBzdHJpbmcpID0+IGZvcm1hdFRhc2tOYW1lKHRhc2spKTtcbi8vICAgICBjb25zdCBpbnB1dCA9IHtcbi8vICAgICAgIHRhc2tzOiB0YXNrSWRMaXN0LFxuLy8gICAgICAgY2x1c3RlcjogY2x1c3RlckFSTixcbi8vICAgICB9O1xuLy8gICAgIGNvbnN0IGNvbW1hbmQgPSBuZXcgRGVzY3JpYmVUYXNrc0NvbW1hbmQoaW5wdXQpO1xuLy8gICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4vLyAgICAgY29uc3QgbGlzdE9mVGFza3NGcm9tUmVzcG9uc2UgPSByZXNwb25zZS50YXNrcztcbi8vICAgICBpZiAobGlzdE9mVGFza3NGcm9tUmVzcG9uc2UgIT0gdW5kZWZpbmVkKSB7XG4vLyAgICAgICBmb3IgKGNvbnN0IHRhc2sgb2YgbGlzdE9mVGFza3NGcm9tUmVzcG9uc2UpIHtcbi8vICAgICAgICAgZm9yIChsZXQgbiA9IDA7IG4gPCB0YXNrLmNvbnRhaW5lcnMhLmxlbmd0aDsgbisrKSB7XG4vLyAgICAgICAgICAgaWYgKHRhc2suY29udGFpbmVycyFbbl0udGFza0FybiEgaW4gdnVsbmVyYWJsZURpZ2VzdHMpIHtcbi8vICAgICAgICAgICAgIHZ1bG5lcmFibGVEaWdlc3RzW3Rhc2suY29udGFpbmVycyFbbl0udGFza0FybiFdLnB1c2goXG4vLyAgICAgICAgICAgICAgIHRhc2suY29udGFpbmVycyFbbl0uaW1hZ2VEaWdlc3QhXG4vLyAgICAgICAgICAgICApO1xuLy8gICAgICAgICAgIH0gZWxzZSB7XG4vLyAgICAgICAgICAgICB2dWxuZXJhYmxlRGlnZXN0c1t0YXNrLmNvbnRhaW5lcnMhW25dLnRhc2tBcm4hXSA9IFtcbi8vICAgICAgICAgICAgICAgdGFzay5jb250YWluZXJzIVtuXS5pbWFnZURpZ2VzdCEsXG4vLyAgICAgICAgICAgICBdO1xuLy8gICAgICAgICAgIH1cbi8vICAgICAgICAgfVxuLy8gICAgICAgfVxuLy8gICAgIH1cbi8vICAgICByZXR1cm4gdnVsbmVyYWJsZURpZ2VzdHM7XG4vLyAgIH1cbi8vICAgcmV0dXJuIHVuZGVmaW5lZDtcbi8vIH07XG5cbi8vIHJldHVybnMgdGhlIG5hbWUgb2YgdGhlIGNsdXN0ZXIgb3IgdW5kZWZpbmVkIGlmIG5vdCBmb3VuZFxuY29uc3QgZ2V0Q2x1c3Rlck5hbWUgPSBhc3luYyAoXG4gIGNsdXN0ZXJBUk46IHN0cmluZ1xuKTogUHJvbWlzZTxzdHJpbmcgfCB1bmRlZmluZWQ+ID0+IHtcbiAgY29uc3QgaW5wdXQgPSB7XG4gICAgY2x1c3RlcnM6IFtjbHVzdGVyQVJOXSxcbiAgfTtcbiAgY29uc3QgY29tbWFuZCA9IG5ldyBEZXNjcmliZUNsdXN0ZXJzQ29tbWFuZChpbnB1dCk7XG4gIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4gIGlmIChyZXNwb25zZSAhPSB1bmRlZmluZWQpIHtcbiAgICByZXR1cm4gcmVzcG9uc2UuY2x1c3RlcnMhWzBdLmNsdXN0ZXJOYW1lITtcbiAgfVxuICByZXR1cm4gdW5kZWZpbmVkO1xufTtcblxuLy8gZmlsdGVycyBsaXN0IG9mIHRhc2tzIHRvIGp1c3QgdnVsbmVyYWJsZSB0YXNrc1xuLy8gdHJ5IHdpdGgganVzdCByZXR1cm5pbmcgYSB0YXNrbGlzdFxuLy8gY29uc3QgZ2V0VnVsbmVyYWJsZVRhc2tMaXN0ID0gYXN5bmMgKFxuLy8gICBldmVudEltYWdlRGlnZXN0OiBzdHJpbmcsXG4vLyAgIGNsdXN0ZXJBUk46IHN0cmluZ1xuLy8gKTogUHJvbWlzZTxzdHJpbmdbXSB8IHVuZGVmaW5lZD4gPT4ge1xuLy8gICBjb25zdCB2dWxuZXJhYmxlVGFza0xpc3Q6IHN0cmluZ1tdID0gW107XG4vLyAgIGNvbnN0IGNsdXN0ZXJOYW1lID0gYXdhaXQgZ2V0Q2x1c3Rlck5hbWUoY2x1c3RlckFSTik7XG4vLyAgIGNvbnN0IHRhc2tMaXN0ID0gYXdhaXQgbGlzdFRhc2tzRnJvbUNsdXN0ZXJBUk4oY2x1c3RlckFSTik7XG4vLyAgIGNvbnNvbGUubG9nKGBUaGUgbGlzdCBvZiB0YXNrczogJHt0YXNrTGlzdC5tYXAoKHRhc2spPT5mb3JtYXRUYXNrTmFtZSh0YXNrKSl9YClcbi8vICAgY29uc3QgZm9ybWF0dGVkVGFza3MgPSB0YXNrTGlzdC5tYXAoKHRhc2spPT5mb3JtYXRUYXNrTmFtZSh0YXNrKSk7XG4vLyAgIGNvbnN0IGlucHV0ID0ge1xuLy8gICAgIHRhc2tzOiBmb3JtYXR0ZWRUYXNrcyxcbi8vICAgfTtcbi8vICAgY29uc3QgY29tbWFuZCA9IG5ldyBEZXNjcmliZVRhc2tzQ29tbWFuZChpbnB1dCk7XG4vLyAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4vLyAgIGNvbnNvbGUubG9nKHJlc3BvbnNlKTtcbi8vICAgaWYgKHRhc2tMaXN0ID09PSB1bmRlZmluZWQpIHtcbi8vICAgICBjb25zb2xlLmxvZyhgTm8gRUNTIHRhc2tzIGZvdW5kIGluIGNsdXN0ZXIgJHtjbHVzdGVyTmFtZX1gKTtcbi8vICAgfSBlbHNlIHtcbi8vICAgICBmb3IgKGNvbnN0IHRhc2sgb2YgdGFza0xpc3QpIHtcbi8vICAgICAgIGNvbnNvbGUubG9nKHRhc2spO1xuLy8gICAgICAgY29uc29sZS5sb2coZm9ybWF0VGFza05hbWUodGFzaykpO1xuLy8gICAgICAgaWYgKGZvcm1hdFRhc2tOYW1lKHRhc2spID09PSBldmVudEltYWdlRGlnZXN0KSB7XG4vLyAgICAgICAgIHZ1bG5lcmFibGVUYXNrTGlzdC5wdXNoKHRhc2spO1xuLy8gICAgICAgfVxuLy8gICAgIH1cbi8vICAgICBjb25zb2xlLmxvZyh2dWxuZXJhYmxlVGFza0xpc3QpO1xuLy8gICAgIHJldHVybiB2dWxuZXJhYmxlVGFza0xpc3Q7XG4vLyAgIH1cbi8vICAgcmV0dXJuIHVuZGVmaW5lZDtcbi8vIH07XG5cbmNvbnN0IGNvbXBhcmVEaWdlc3RzID0gKFxuICBldmVudEltYWdlRGlnZXN0OiBzdHJpbmcsXG4gIGltYWdlRGlnZXN0OiBzdHJpbmdcbik6IGJvb2xlYW4gPT4ge1xuICByZXR1cm4gZXZlbnRJbWFnZURpZ2VzdCA9PT0gaW1hZ2VEaWdlc3Q7XG59O1xuXG4vLyB0YWtlcyBsaXN0IG9mIHZ1bG5lcmFibGUgdGFzayBBUk4gYW5kIGV2ZW50aW1hZ2VkaWdlc3Rcbi8vIHByaW50cyB0aGUgY29udGFpbmVyIG5hbWUgYWxvbmcgd2l0aCB0aGUgdGFzayBBUk5cbi8vIGNvbnN0IHByaW50TG9nTWVzc2FnZSA9IGFzeW5jIChcbi8vICAgbGlzdE9mVnVsbmVyYWJsZVRhc2tzOiBzdHJpbmdbXSB8IHVuZGVmaW5lZCxcbi8vICAgZXZlbnRJbWdEaWdlc3Q6IHN0cmluZ1xuLy8gKSA9PiB7XG4vLyAgIGlmIChsaXN0T2ZWdWxuZXJhYmxlVGFza3MgPT0gdW5kZWZpbmVkKSB7XG4vLyAgICAgY29uc29sZS5sb2coXCJWdWxuZXJhYmxlIHRhc2sgbGlzdCBpcyB1bmRlZmluZWQuXCIpO1xuLy8gICB9IGVsc2UgaWYgKGxpc3RPZlZ1bG5lcmFibGVUYXNrcy5sZW5ndGggPT09IDApIHtcbi8vICAgICBjb25zb2xlLmxvZyhgTm8gRUNTIHRhc2tzIHdpdGggdnVsbmVyYWJsZSBpbWFnZSAke2V2ZW50SW1nRGlnZXN0fSBmb3VuZC5gKTtcbi8vICAgfSBlbHNlIHtcbi8vICAgICAvLyBmb3IgKGNvbnN0IHZ1bG5EaWdlc3Qgb2YgbGlzdE9mVnVsbmVyYWJsZVRhc2tzKSB7XG4vLyAgICAgLy8gICBpZiAoY29tcGFyZURpZ2VzdHModnVsbkRpZ2VzdCwgZXZlbnRJbWdEaWdlc3QpKSB7XG4vLyAgICAgLy8gICAgIGNvbnNvbGUubG9nKFxuLy8gICAgIC8vICAgICAgIGBFQ1MgdGFzayB3aXRoIHZ1bG5lcmFibGUgaW1hZ2UgJHtldmVudEltZ0RpZ2VzdH0gZm91bmQ6ICR7dnVsbkRpZ2VzdH1gXG4vLyAgICAgLy8gICAgICk7XG4vLyAgICAgLy8gICAgIGNvbnNvbGUubG9nKGAke3Z1bG5EaWdlc3R9YCk7XG4vLyAgICAgLy8gICAgIC8vIHByaW50IHRoZSBlbnRpcmUgdGFzayBkZXNjcmlwdGlvblxuLy8gICAgIC8vICAgfVxuLy8gICAgIC8vIH1cbi8vICAgICBjb25zdCBpbnB1dCA9IHtcbi8vICAgICAgIHRhc2tzOiBsaXN0T2ZWdWxuZXJhYmxlVGFza3MsXG4vLyAgICAgfTtcbi8vICAgICBjb25zdCBjb21tYW5kID0gbmV3IERlc2NyaWJlVGFza3NDb21tYW5kKGlucHV0KTtcbi8vICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGVjcy5zZW5kKGNvbW1hbmQpO1xuLy8gICAgIGZvciAoY29uc3QgdGFzayBvZiByZXNwb25zZS50YXNrcyEpIHtcbi8vICAgICAgIGZvciAoY29uc3QgY29udGFpbmVyIG9mIHRhc2suY29udGFpbmVycyEpIHtcbi8vICAgICAgICAgLy8gcHJpbnQgdGhlIHRhc2sgQVJOXG4vLyAgICAgICAgIGNvbnNvbGUubG9nKGBDb250YWluZXIgJHtjb250YWluZXIubmFtZX0gZm91bmQgd2l0aFxuLy8gICAgICAgICAgICAgICAgICB2dWxuZXJhYmxlIGltYWdlICR7ZXZlbnRJbWdEaWdlc3R9LiBSZWZlciB0byB0YXNrIEFSTiAke3Rhc2sudGFza0Fybn1gKTtcbi8vICAgICAgICAgLy8gcHJpbnQgdGhlIGVudGlyZSBjb250YWluZXIgaW5mb3JtYXRpb25cbi8vICAgICAgICAgY29uc29sZS5sb2coY29udGFpbmVyKTtcbi8vICAgICAgIH1cbi8vICAgICB9XG4vLyAgIH1cbi8vIH07XG5cbmV4cG9ydCBjb25zdCBoYW5kbGVyID0gYXN5bmMgZnVuY3Rpb24gKFxuICBldmVudDogRXZlbnRCcmlkZ2VFdmVudDxzdHJpbmcsIGFueT4sXG4gIGNvbnRleHQ6IENvbnRleHQsXG4gIGNhbGxiYWNrOiBDYWxsYmFja1xuKSB7XG4gIC8vIGNvbnNvbGUubG9nKGBcbiAgLy8gIyMjIyMjIyMjIyMjIyMjXG4gIC8vICR7SlNPTi5zdHJpbmdpZnkoZXZlbnQpfVxuICAvLyAjIyMjIyMjIyMjIyMjIyNcbiAgLy8gYClcbiAgY29uc3QgZXZlbnRJbWFnZUFSTjogc3RyaW5nID0gZXZlbnQucmVzb3VyY2VzWzBdO1xuICAvLyBjb25zdCBldmVudEltYWdlRGlnZXN0OiBzdHJpbmcgPSBldmVudC5kZXRhaWwucmVzb3VyY2VzLmF3c0VjckNvbnRhaW5lckltYWdlLmltYWdlSGFzaFxuICBjb25zdCBldmVudEltYWdlQVJORGlnZXN0SW5kZXggPSBldmVudEltYWdlQVJOLmxhc3RJbmRleE9mKFwiL3NoYTI1NjpcIik7XG4gIGNvbnN0IGV2ZW50SW1hZ2VEaWdlc3QgPSBldmVudEltYWdlQVJOLnNsaWNlKGV2ZW50SW1hZ2VBUk5EaWdlc3RJbmRleCArIDEpOyAvLyBhZGRlZCArIDEgdG8gcmVtb3ZlIHRoZSAvIGluIHRoZSBzdHJpbmdcblxuICBjb25zdCBjbHVzdGVyTGlzdCA9IGF3YWl0IGdldExpc3RPZkNsdXN0ZXJBUk4oKTsgLy8gZ2V0IGxpc3Qgb2YgY2x1c3RlcnNcbiAgbGV0IGFsbFRhc2tzIDogVGFza1tdIDsgLy8gZW1wdHkgbGlzdCB0byBob2xkIGFsbCB0YXNrIGRlc2NyaXB0aW9uc1xuICBmb3IgKGNvbnN0IGNsdXN0ZXIgb2YgY2x1c3Rlckxpc3QpIHtcbiAgICBjb25zdCB0YXNrSWRzID0gYXdhaXQgbGlzdFRhc2tzRnJvbUNsdXN0ZXJBUk4oY2x1c3Rlcik7IC8vIGdldHRpbmcgYWxsIHRhc2sgaWRzIHBlciBjbHVzdGVyXG4gICAgaWYgKHRhc2tJZHMgIT0gdW5kZWZpbmVkKSB7XG4gICAgICBjb25zdCB0YXNrRGVzY3JpcHRpb25zID0gYXdhaXQgZ2V0VGFza0Rlc2NyaXB0aW9ucyhjbHVzdGVyLCB0YXNrSWRzKTsgLy8gZ2V0dGluZyBhbGwgdGFzayBkZXNjcmlwdGlvbnMgcGVyIGNsdXN0ZXJcbiAgICAgIGlmICh0YXNrRGVzY3JpcHRpb25zICE9IHVuZGVmaW5lZCkge1xuICAgICAgICBhbGxUYXNrcyA9IGFsbFRhc2tzIS5jb25jYXQodGFza0Rlc2NyaXB0aW9ucyEpO1xuICAgICAgfVxuICAgIH1cbiAgfVxuICBmb3IgKGNvbnN0IHRhc2sgb2YgYWxsVGFza3MhKSB7IFxuICAgIGlmICh0YXNrLmNvbnRhaW5lcnMpeyBcbiAgICAgIGZvciAoY29uc3QgY29udGFpbmVyIG9mIHRhc2suY29udGFpbmVycyEpIHtcbiAgICAgICAgaWYgKGNvbXBhcmVEaWdlc3RzKGNvbnRhaW5lci5pbWFnZURpZ2VzdCEsIGV2ZW50SW1hZ2VEaWdlc3QpKSB7XG4gICAgICAgICAgY29uc29sZS5sb2coYCR7Y29udGFpbmVyLm5hbWV9IGhhcyBiZWVuIGZvdW5kIHRvIGhhdmUgYSBuZXcgdnVsbmVyYWJpbGl0eS4gVGhlIGFzc29jaWF0ZWQgaW1hZ2UgY2FuIGJlIGZvdW5kIGhlcmU6ICR7Y29udGFpbmVyLmltYWdlfX1gKVxuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuICB9XG59O1xuIl19