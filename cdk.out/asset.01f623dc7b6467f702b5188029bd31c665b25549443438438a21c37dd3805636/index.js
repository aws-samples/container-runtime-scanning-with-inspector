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
        if (response === undefined) {
            return undefined;
        }
        else {
            nextToken = response.nextToken;
            if (response.taskArns != undefined) {
                taskList = taskList.concat(response.taskArns);
            }
        }
    } while (nextToken);
    return taskList;
};
const chunkArray = (array, chunkSize) => {
    const chunks = [];
    let index = 0;
    while (index < array.length) {
        chunks.push(array.slice(index, index + chunkSize));
        index += chunkSize;
    }
    return chunks;
};
const getTaskDescriptions = async (clusterARN, taskIdList) => {
    if (taskIdList.length <= 100) {
        const input = {
            tasks: taskIdList,
            cluster: clusterARN,
        };
        const command = new client_ecs_1.DescribeTasksCommand(input);
        const response = await ecs.send(command);
        if (response != undefined) {
            return response.tasks;
        }
    }
    else {
        const taskChunks = chunkArray(taskIdList, 100);
        let taskDescriptions = [];
        for (const taskChunk of taskChunks) {
            const input = {
                tasks: taskChunk,
                cluster: clusterARN,
            };
            const command = new client_ecs_1.DescribeTasksCommand(input);
            const response = await ecs.send(command);
            if (response != undefined) {
                taskDescriptions = taskDescriptions.concat(response.tasks);
            }
        }
        return taskDescriptions;
    }
    return undefined;
};
// compares event image digest with task image digest
const compareDigests = (eventImageDigest, imageDigest) => {
    return eventImageDigest === imageDigest;
};
// gets all task descriptions from all clusters
const getAllTaskDescriptions = async (clusterARNs) => {
    let returnTaskList = [];
    for (const cluster of clusterARNs) {
        const taskIds = await listTasksFromClusterARN(cluster);
        if (taskIds != undefined) {
            const taskDescriptions = await getTaskDescriptions(cluster, taskIds);
            if (taskDescriptions != undefined) {
                returnTaskList = returnTaskList.concat(taskDescriptions);
            }
        }
    }
    return returnTaskList;
};
// main lambda function
const handler = async function (event, context, callback) {
    const eventImageHash = event.detail.resources[0].details.awsEcrContainerImage.imageHash;
    // const eventImageARN: string = event.resources[0];
    // const eventImageARNDigestIndex = eventImageARN.lastIndexOf("/sha256:");
    // const eventImageDigest = eventImageARN.slice(eventImageARNDigestIndex + 1);
    try {
        const clusterList = await getListOfClusterARN();
        const allTasks = await getAllTaskDescriptions(clusterList);
        if (allTasks != undefined) {
            for (const task of allTasks) {
                if (task.containers) {
                    for (const container of task.containers) {
                        if (compareDigests(container.imageDigest, eventImageHash)) {
                            console.log(`Container: ${container.name} has been found to have a new vulnerability. The associated image can be found here: ${container.image}`);
                        }
                        else {
                            console.log(`Container: ${container.name} has not been found to have a new vulnerability. The image digest of the image with the new vulnerability is: ${eventImageHash}`);
                        }
                    }
                }
            }
        }
    }
    catch (error) {
        console.error(error);
    }
};
exports.handler = handler;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyJpbmRleC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFDQSxvREFPNkI7QUFFN0IsTUFBTSxHQUFHLEdBQUcsSUFBSSxzQkFBUyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0FBRTlCLDhCQUE4QjtBQUM5QixNQUFNLG1CQUFtQixHQUFHLEtBQUssSUFBdUIsRUFBRTtJQUN4RCxJQUFJLFdBQVcsR0FBYSxFQUFFLENBQUM7SUFDL0IsSUFBSSxTQUE2QixDQUFDO0lBRWxDLE1BQU0sS0FBSyxHQUFHLEVBQUUsQ0FBQztJQUNqQixNQUFNLE9BQU8sR0FBRyxJQUFJLGdDQUFtQixDQUFDLEtBQUssQ0FBQyxDQUFDO0lBQy9DLEdBQUc7UUFDRCxNQUFNLFFBQVEsR0FBRyxNQUFNLEdBQUcsQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUM7UUFDekMsSUFBSSxRQUFRLElBQUksU0FBUyxFQUFFO1lBQ3pCLFNBQVMsR0FBRyxRQUFRLENBQUMsU0FBUyxDQUFDO1lBQy9CLFdBQVcsR0FBRyxXQUFXLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxXQUFZLENBQUMsQ0FBQztTQUN6RDtLQUNGLFFBQVEsU0FBUyxFQUFFO0lBQ3BCLE9BQU8sV0FBVyxDQUFDO0FBQ3JCLENBQUMsQ0FBQztBQUVGLHNEQUFzRDtBQUN0RCxNQUFNLHVCQUF1QixHQUFHLEtBQUssRUFBRSxXQUFtQixFQUFFLEVBQUU7SUFDNUQsSUFBSSxRQUFRLEdBQWEsRUFBRSxDQUFDO0lBQzVCLElBQUksU0FBNkIsQ0FBQztJQUVsQyxHQUFHO1FBQ0QsTUFBTSxLQUFLLEdBQUc7WUFDWixPQUFPLEVBQUUsV0FBVztTQUNyQixDQUFDO1FBQ0YsTUFBTSxPQUFPLEdBQUcsSUFBSSw2QkFBZ0IsQ0FBQyxLQUFLLENBQUMsQ0FBQztRQUM1QyxNQUFNLFFBQVEsR0FBRyxNQUFNLEdBQUcsQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUM7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QUU7UUFDZCxPQUFPLENBQUMsS0FBSyxDQUFDLEtBQUssQ0FBQyxDQUFDO0tBQ3RCO0FBQ0gsQ0FBQyxDQUFDO0FBakNXLFFBQUEsT0FBTyxXQWlDbEIiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBDYWxsYmFjaywgRXZlbnRCcmlkZ2VFdmVudCwgQ29udGV4dCB9IGZyb20gXCJhd3MtbGFtYmRhXCI7XG5pbXBvcnQge1xuICBFQ1NDbGllbnQsXG4gIExpc3RDbHVzdGVyc0NvbW1hbmQsXG4gIExpc3RUYXNrc0NvbW1hbmQsXG4gIERlc2NyaWJlVGFza3NDb21tYW5kLFxuICBEZXNjcmliZUNsdXN0ZXJzQ29tbWFuZCxcbiAgVGFzayxcbn0gZnJvbSBcIkBhd3Mtc2RrL2NsaWVudC1lY3NcIjtcblxuY29uc3QgZWNzID0gbmV3IEVDU0NsaWVudCh7fSk7XG5cbi8vIHJldHVybnMgbGlzdCBvZiBjbHVzdGVyIEFSTlxuY29uc3QgZ2V0TGlzdE9mQ2x1c3RlckFSTiA9IGFzeW5jICgpOiBQcm9taXNlPHN0cmluZ1tdPiA9PiB7XG4gIGxldCBjbHVzdGVyTGlzdDogc3RyaW5nW10gPSBbXTtcbiAgbGV0IG5leHRUb2tlbjogc3RyaW5nIHwgdW5kZWZpbmVkO1xuXG4gIGNvbnN0IGlucHV0ID0ge307XG4gIGNvbnN0IGNvbW1hbmQgPSBuZXcgTGlzdENsdXN0ZXJzQ29tbWFuZChpbnB1dCk7XG4gIGRvIHtcbiAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGVjcy5zZW5kKGNvbW1hbmQpO1xuICAgIGlmIChyZXNwb25zZSAhPSB1bmRlZmluZWQpIHtcbiAgICAgIG5leHRUb2tlbiA9IHJlc3BvbnNlLm5leHRUb2tlbjtcbiAgICAgIGNsdXN0ZXJMaXN0ID0gY2x1c3Rlckxpc3QuY29uY2F0KHJlc3BvbnNlLmNsdXN0ZXJBcm5zISk7XG4gICAgfVxuICB9IHdoaWxlIChuZXh0VG9rZW4pO1xuICByZXR1cm4gY2x1c3Rlckxpc3Q7XG59O1xuXG4vLyByZXR1cm5zIGxpc3Qgb2YgQUxMIHRhc2sgQVJOIGZyb20gc3BlY2lmaWVkIGNsdXN0ZXJcbmNvbnN0IGxpc3RUYXNrc0Zyb21DbHVzdGVyQVJOID0gYXN5bmMgKGNsdXN0ZXJOYW1lOiBzdHJpbmcpID0+IHtcbiAgbGV0IHRhc2tMaXN0OiBzdHJpbmdbXSA9IFtdO1xuICBsZXQgbmV4dFRva2VuOiBzdHJpbmcgfCB1bmRlZmluZWQ7XG5cbiAgZG8ge1xuICAgIGNvbnN0IGlucHV0ID0ge1xuICAgICAgY2x1c3RlcjogY2x1c3Rlck5hbWUsXG4gICAgfTtcbiAgICBjb25zdCBjb21tYW5kID0gbmV3IExpc3RUYXNrc0NvbW1hbmQoaW5wdXQpO1xuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4gICAgaWYgKHJlc3BvbnNlID09PSB1bmRlZmluZWQpIHtcbiAgICAgIHJldHVybiB1bmRlZmluZWQ7XG4gICAgfSBlbHNlIHtcbiAgICAgIG5leHRUb2tlbiA9IHJlc3BvbnNlLm5leHRUb2tlbjtcbiAgICAgIGlmIChyZXNwb25zZS50YXNrQXJucyAhPSB1bmRlZmluZWQpIHtcbiAgICAgICAgdGFza0xpc3QgPSB0YXNrTGlzdC5jb25jYXQocmVzcG9uc2UudGFza0FybnMpO1xuICAgICAgfVxuICAgIH1cbiAgfSB3aGlsZSAobmV4dFRva2VuKTtcbiAgcmV0dXJuIHRhc2tMaXN0O1xufTtcblxuY29uc3QgY2h1bmtBcnJheSA9IChhcnJheTogYW55W10sIGNodW5rU2l6ZTogbnVtYmVyKTogYW55W11bXSA9PiB7XG4gIGNvbnN0IGNodW5rczogYW55W11bXSA9IFtdO1xuICBsZXQgaW5kZXggPSAwXG4gIHdoaWxlIChpbmRleCA8IGFycmF5Lmxlbmd0aCkge1xuICAgIGNodW5rcy5wdXNoKGFycmF5LnNsaWNlKGluZGV4LCBpbmRleCArIGNodW5rU2l6ZSkpO1xuICAgIGluZGV4ICs9IGNodW5rU2l6ZTtcbiAgfVxuICByZXR1cm4gY2h1bmtzO1xufVxuXG5jb25zdCBnZXRUYXNrRGVzY3JpcHRpb25zID0gYXN5bmMgKFxuICBjbHVzdGVyQVJOOiBzdHJpbmcsXG4gIHRhc2tJZExpc3Q6IHN0cmluZ1tdXG4pOiBQcm9taXNlPFRhc2tbXSB8IHVuZGVmaW5lZD4gPT4ge1xuICBpZiAodGFza0lkTGlzdC5sZW5ndGggPD0gMTAwKSB7XG4gICAgY29uc3QgaW5wdXQgPSB7XG4gICAgICB0YXNrczogdGFza0lkTGlzdCxcbiAgICAgIGNsdXN0ZXI6IGNsdXN0ZXJBUk4sXG4gICAgfTtcbiAgICBjb25zdCBjb21tYW5kID0gbmV3IERlc2NyaWJlVGFza3NDb21tYW5kKGlucHV0KTtcbiAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGVjcy5zZW5kKGNvbW1hbmQpO1xuICAgIGlmIChyZXNwb25zZSAhPSB1bmRlZmluZWQpIHtcbiAgICAgIHJldHVybiByZXNwb25zZS50YXNrcztcbiAgICB9XG4gIH0gZWxzZSB7XG4gICAgY29uc3QgdGFza0NodW5rcyA9IGNodW5rQXJyYXkodGFza0lkTGlzdCwgMTAwKTtcbiAgICBsZXQgdGFza0Rlc2NyaXB0aW9uczogVGFza1tdID0gW107XG4gICAgZm9yIChjb25zdCB0YXNrQ2h1bmsgb2YgdGFza0NodW5rcykge1xuICAgICAgY29uc3QgaW5wdXQgPSB7XG4gICAgICAgIHRhc2tzOiB0YXNrQ2h1bmssXG4gICAgICAgIGNsdXN0ZXI6IGNsdXN0ZXJBUk4sXG4gICAgICB9O1xuICAgICAgY29uc3QgY29tbWFuZCA9IG5ldyBEZXNjcmliZVRhc2tzQ29tbWFuZChpbnB1dCk7XG4gICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGVjcy5zZW5kKGNvbW1hbmQpO1xuICAgICAgaWYgKHJlc3BvbnNlICE9IHVuZGVmaW5lZCkge1xuICAgICAgICB0YXNrRGVzY3JpcHRpb25zID0gdGFza0Rlc2NyaXB0aW9ucy5jb25jYXQocmVzcG9uc2UudGFza3MhKTtcbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIHRhc2tEZXNjcmlwdGlvbnM7XG4gIH0gXG4gIHJldHVybiB1bmRlZmluZWQ7XG59O1xuXG4vLyBjb21wYXJlcyBldmVudCBpbWFnZSBkaWdlc3Qgd2l0aCB0YXNrIGltYWdlIGRpZ2VzdFxuY29uc3QgY29tcGFyZURpZ2VzdHMgPSAoXG4gIGV2ZW50SW1hZ2VEaWdlc3Q6IHN0cmluZyxcbiAgaW1hZ2VEaWdlc3Q6IHN0cmluZ1xuKTogYm9vbGVhbiA9PiB7XG4gIHJldHVybiBldmVudEltYWdlRGlnZXN0ID09PSBpbWFnZURpZ2VzdDtcbn07XG5cbi8vIGdldHMgYWxsIHRhc2sgZGVzY3JpcHRpb25zIGZyb20gYWxsIGNsdXN0ZXJzXG5jb25zdCBnZXRBbGxUYXNrRGVzY3JpcHRpb25zID0gYXN5bmMgKGNsdXN0ZXJBUk5zOiBzdHJpbmdbXSk6IFByb21pc2U8VGFza1tdPiA9PiB7XG4gIGxldCByZXR1cm5UYXNrTGlzdDogVGFza1tdID0gW107XG4gIGZvciAoY29uc3QgY2x1c3RlciBvZiBjbHVzdGVyQVJOcykge1xuICAgIGNvbnN0IHRhc2tJZHMgPSBhd2FpdCBsaXN0VGFza3NGcm9tQ2x1c3RlckFSTihjbHVzdGVyKTsgXG4gICAgaWYgKHRhc2tJZHMgIT0gdW5kZWZpbmVkKSB7XG4gICAgICBjb25zdCB0YXNrRGVzY3JpcHRpb25zID0gYXdhaXQgZ2V0VGFza0Rlc2NyaXB0aW9ucyhjbHVzdGVyLCB0YXNrSWRzKTsgXG4gICAgICBpZiAodGFza0Rlc2NyaXB0aW9ucyAhPSB1bmRlZmluZWQpIHtcbiAgICAgICAgcmV0dXJuVGFza0xpc3QgPSByZXR1cm5UYXNrTGlzdC5jb25jYXQodGFza0Rlc2NyaXB0aW9ucyEpO1xuICAgICAgfVxuICAgIH1cbiAgfSByZXR1cm4gcmV0dXJuVGFza0xpc3Q7XG59XG5cblxuLy8gbWFpbiBsYW1iZGEgZnVuY3Rpb25cbmV4cG9ydCBjb25zdCBoYW5kbGVyID0gYXN5bmMgZnVuY3Rpb24gKFxuICBldmVudDogRXZlbnRCcmlkZ2VFdmVudDxzdHJpbmcsIGFueT4sXG4gIGNvbnRleHQ6IENvbnRleHQsXG4gIGNhbGxiYWNrOiBDYWxsYmFja1xuKSB7XG4gIGNvbnN0IGV2ZW50SW1hZ2VIYXNoOiBzdHJpbmcgPSBldmVudC5kZXRhaWwucmVzb3VyY2VzWzBdLmRldGFpbHMuYXdzRWNyQ29udGFpbmVySW1hZ2UuaW1hZ2VIYXNoO1xuICAvLyBjb25zdCBldmVudEltYWdlQVJOOiBzdHJpbmcgPSBldmVudC5yZXNvdXJjZXNbMF07XG4gIC8vIGNvbnN0IGV2ZW50SW1hZ2VBUk5EaWdlc3RJbmRleCA9IGV2ZW50SW1hZ2VBUk4ubGFzdEluZGV4T2YoXCIvc2hhMjU2OlwiKTtcbiAgLy8gY29uc3QgZXZlbnRJbWFnZURpZ2VzdCA9IGV2ZW50SW1hZ2VBUk4uc2xpY2UoZXZlbnRJbWFnZUFSTkRpZ2VzdEluZGV4ICsgMSk7XG5cbiAgdHJ5IHtcbiAgICBjb25zdCBjbHVzdGVyTGlzdCA9IGF3YWl0IGdldExpc3RPZkNsdXN0ZXJBUk4oKTsgXG4gICAgY29uc3QgYWxsVGFza3MgPSBhd2FpdCBnZXRBbGxUYXNrRGVzY3JpcHRpb25zKGNsdXN0ZXJMaXN0KTsgXG4gICAgaWYgKGFsbFRhc2tzICE9IHVuZGVmaW5lZCkge1xuICAgICAgZm9yIChjb25zdCB0YXNrIG9mIGFsbFRhc2tzISkge1xuICAgICAgICBpZiAodGFzay5jb250YWluZXJzKSB7XG4gICAgICAgICAgZm9yIChjb25zdCBjb250YWluZXIgb2YgdGFzay5jb250YWluZXJzISkge1xuICAgICAgICAgICAgaWYgKGNvbXBhcmVEaWdlc3RzKGNvbnRhaW5lci5pbWFnZURpZ2VzdCEsIGV2ZW50SW1hZ2VIYXNoKSkge1xuICAgICAgICAgICAgICBjb25zb2xlLmxvZyhcbiAgICAgICAgICAgICAgICBgQ29udGFpbmVyOiAke2NvbnRhaW5lci5uYW1lfSBoYXMgYmVlbiBmb3VuZCB0byBoYXZlIGEgbmV3IHZ1bG5lcmFiaWxpdHkuIFRoZSBhc3NvY2lhdGVkIGltYWdlIGNhbiBiZSBmb3VuZCBoZXJlOiAke2NvbnRhaW5lci5pbWFnZX1gXG4gICAgICAgICAgICAgICk7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBjb25zb2xlLmxvZyhcbiAgICAgICAgICAgICAgICBgQ29udGFpbmVyOiAke2NvbnRhaW5lci5uYW1lfSBoYXMgbm90IGJlZW4gZm91bmQgdG8gaGF2ZSBhIG5ldyB2dWxuZXJhYmlsaXR5LiBUaGUgaW1hZ2UgZGlnZXN0IG9mIHRoZSBpbWFnZSB3aXRoIHRoZSBuZXcgdnVsbmVyYWJpbGl0eSBpczogJHtldmVudEltYWdlSGFzaH1gXG4gICAgICAgICAgICAgICk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuICB9IGNhdGNoIChlcnJvcikge1xuICAgIGNvbnNvbGUuZXJyb3IoZXJyb3IpO1xuICB9XG59OyJdfQ==