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
    const eventImageARN = event.resources[0];
    const eventImageARNDigestIndex = eventImageARN.lastIndexOf("/sha256:");
    const eventImageDigest = eventImageARN.slice(eventImageARNDigestIndex + 1);
    try {
        const clusterList = await getListOfClusterARN();
        const allTasks = await getAllTaskDescriptions(clusterList);
        if (allTasks != undefined) {
            for (const task of allTasks) {
                if (task.containers) {
                    for (const container of task.containers) {
                        if (compareDigests(container.imageDigest, eventImageDigest)) {
                            console.log(`Container: ${container.name} has been found to have a new vulnerability. The associated image can be found here: ${container.image}`);
                        }
                        else {
                            console.log(`Container: ${container.name} has not been found to have a new vulnerability. The associated image can be found here: ${container.image}`);
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyJpbmRleC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFDQSxvREFPNkI7QUFFN0IsTUFBTSxHQUFHLEdBQUcsSUFBSSxzQkFBUyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0FBRTlCLDhCQUE4QjtBQUM5QixNQUFNLG1CQUFtQixHQUFHLEtBQUssSUFBdUIsRUFBRTtJQUN4RCxJQUFJLFdBQVcsR0FBYSxFQUFFLENBQUM7SUFDL0IsSUFBSSxTQUE2QixDQUFDO0lBRWxDLE1BQU0sS0FBSyxHQUFHLEVBQUUsQ0FBQztJQUNqQixNQUFNLE9BQU8sR0FBRyxJQUFJLGdDQUFtQixDQUFDLEtBQUssQ0FBQyxDQUFDO0lBQy9DLEdBQUc7UUFDRCxNQUFNLFFBQVEsR0FBRyxNQUFNLEdBQUcsQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUM7UUFDekMsSUFBSSxRQUFRLElBQUksU0FBUyxFQUFFO1lBQ3pCLFNBQVMsR0FBRyxRQUFRLENBQUMsU0FBUyxDQUFDO1lBQy9CLFdBQVcsR0FBRyxXQUFXLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxXQUFZLENBQUMsQ0FBQztTQUN6RDtLQUNGLFFBQVEsU0FBUyxFQUFFO0lBQ3BCLE9BQU8sV0FBVyxDQUFDO0FBQ3JCLENBQUMsQ0FBQztBQUVGLHNEQUFzRDtBQUN0RCxNQUFNLHVCQUF1QixHQUFHLEtBQUssRUFBRSxXQUFtQixFQUFFLEVBQUU7SUFDNUQsSUFBSSxRQUFRLEdBQWEsRUFBRSxDQUFDO0lBQzVCLElBQUksU0FBNkIsQ0FBQztJQUVsQyxHQUFHO1FBQ0QsTUFBTSxLQUFLLEdBQUc7WUFDWixPQUFPLEVBQUUsV0FBVztTQUNyQixDQUFDO1FBQ0YsTUFBTSxPQUFPLEdBQUcsSUFBSSw2QkFBZ0IsQ0FBQyxLQUFLLENBQUMsQ0FBQztRQUM1QyxNQUFNLFFBQVEsR0FBRyxNQUFNLEdBQUcsQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUM7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QzFJLENBQUM7eUJBQ0g7cUJBQ0Y7aUJBQ0Y7YUFDRjtTQUNGO0tBQ0Y7SUFBQyxPQUFPLEtBQUssRUFBRTtRQUNkLE9BQU8sQ0FBQyxLQUFLLENBQUMsS0FBSyxDQUFDLENBQUM7S0FDdEI7QUFDSCxDQUFDLENBQUM7QUFoQ1csUUFBQSxPQUFPLFdBZ0NsQiIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IENhbGxiYWNrLCBFdmVudEJyaWRnZUV2ZW50LCBDb250ZXh0IH0gZnJvbSBcImF3cy1sYW1iZGFcIjtcbmltcG9ydCB7XG4gIEVDU0NsaWVudCxcbiAgTGlzdENsdXN0ZXJzQ29tbWFuZCxcbiAgTGlzdFRhc2tzQ29tbWFuZCxcbiAgRGVzY3JpYmVUYXNrc0NvbW1hbmQsXG4gIERlc2NyaWJlQ2x1c3RlcnNDb21tYW5kLFxuICBUYXNrLFxufSBmcm9tIFwiQGF3cy1zZGsvY2xpZW50LWVjc1wiO1xuXG5jb25zdCBlY3MgPSBuZXcgRUNTQ2xpZW50KHt9KTtcblxuLy8gcmV0dXJucyBsaXN0IG9mIGNsdXN0ZXIgQVJOXG5jb25zdCBnZXRMaXN0T2ZDbHVzdGVyQVJOID0gYXN5bmMgKCk6IFByb21pc2U8c3RyaW5nW10+ID0+IHtcbiAgbGV0IGNsdXN0ZXJMaXN0OiBzdHJpbmdbXSA9IFtdO1xuICBsZXQgbmV4dFRva2VuOiBzdHJpbmcgfCB1bmRlZmluZWQ7XG5cbiAgY29uc3QgaW5wdXQgPSB7fTtcbiAgY29uc3QgY29tbWFuZCA9IG5ldyBMaXN0Q2x1c3RlcnNDb21tYW5kKGlucHV0KTtcbiAgZG8ge1xuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4gICAgaWYgKHJlc3BvbnNlICE9IHVuZGVmaW5lZCkge1xuICAgICAgbmV4dFRva2VuID0gcmVzcG9uc2UubmV4dFRva2VuO1xuICAgICAgY2x1c3Rlckxpc3QgPSBjbHVzdGVyTGlzdC5jb25jYXQocmVzcG9uc2UuY2x1c3RlckFybnMhKTtcbiAgICB9XG4gIH0gd2hpbGUgKG5leHRUb2tlbik7XG4gIHJldHVybiBjbHVzdGVyTGlzdDtcbn07XG5cbi8vIHJldHVybnMgbGlzdCBvZiBBTEwgdGFzayBBUk4gZnJvbSBzcGVjaWZpZWQgY2x1c3RlclxuY29uc3QgbGlzdFRhc2tzRnJvbUNsdXN0ZXJBUk4gPSBhc3luYyAoY2x1c3Rlck5hbWU6IHN0cmluZykgPT4ge1xuICBsZXQgdGFza0xpc3Q6IHN0cmluZ1tdID0gW107XG4gIGxldCBuZXh0VG9rZW46IHN0cmluZyB8IHVuZGVmaW5lZDtcblxuICBkbyB7XG4gICAgY29uc3QgaW5wdXQgPSB7XG4gICAgICBjbHVzdGVyOiBjbHVzdGVyTmFtZSxcbiAgICB9O1xuICAgIGNvbnN0IGNvbW1hbmQgPSBuZXcgTGlzdFRhc2tzQ29tbWFuZChpbnB1dCk7XG4gICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBlY3Muc2VuZChjb21tYW5kKTtcbiAgICBpZiAocmVzcG9uc2UgPT09IHVuZGVmaW5lZCkge1xuICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICB9IGVsc2Uge1xuICAgICAgbmV4dFRva2VuID0gcmVzcG9uc2UubmV4dFRva2VuO1xuICAgICAgaWYgKHJlc3BvbnNlLnRhc2tBcm5zICE9IHVuZGVmaW5lZCkge1xuICAgICAgICB0YXNrTGlzdCA9IHRhc2tMaXN0LmNvbmNhdChyZXNwb25zZS50YXNrQXJucyk7XG4gICAgICB9XG4gICAgfVxuICB9IHdoaWxlIChuZXh0VG9rZW4pO1xuICByZXR1cm4gdGFza0xpc3Q7XG59O1xuXG5jb25zdCBjaHVua0FycmF5ID0gKGFycmF5OiBhbnlbXSwgY2h1bmtTaXplOiBudW1iZXIpOiBhbnlbXVtdID0+IHtcbiAgY29uc3QgY2h1bmtzOiBhbnlbXVtdID0gW107XG4gIGxldCBpbmRleCA9IDBcbiAgd2hpbGUgKGluZGV4IDwgYXJyYXkubGVuZ3RoKSB7XG4gICAgY2h1bmtzLnB1c2goYXJyYXkuc2xpY2UoaW5kZXgsIGluZGV4ICsgY2h1bmtTaXplKSk7XG4gICAgaW5kZXggKz0gY2h1bmtTaXplO1xuICB9XG4gIHJldHVybiBjaHVua3M7XG59XG5cbmNvbnN0IGdldFRhc2tEZXNjcmlwdGlvbnMgPSBhc3luYyAoXG4gIGNsdXN0ZXJBUk46IHN0cmluZyxcbiAgdGFza0lkTGlzdDogc3RyaW5nW11cbik6IFByb21pc2U8VGFza1tdIHwgdW5kZWZpbmVkPiA9PiB7XG4gIGlmICh0YXNrSWRMaXN0Lmxlbmd0aCA8PSAxMDApIHtcbiAgICBjb25zdCBpbnB1dCA9IHtcbiAgICAgIHRhc2tzOiB0YXNrSWRMaXN0LFxuICAgICAgY2x1c3RlcjogY2x1c3RlckFSTixcbiAgICB9O1xuICAgIGNvbnN0IGNvbW1hbmQgPSBuZXcgRGVzY3JpYmVUYXNrc0NvbW1hbmQoaW5wdXQpO1xuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4gICAgaWYgKHJlc3BvbnNlICE9IHVuZGVmaW5lZCkge1xuICAgICAgcmV0dXJuIHJlc3BvbnNlLnRhc2tzO1xuICAgIH1cbiAgfSBlbHNlIHtcbiAgICBjb25zdCB0YXNrQ2h1bmtzID0gY2h1bmtBcnJheSh0YXNrSWRMaXN0LCAxMDApO1xuICAgIGxldCB0YXNrRGVzY3JpcHRpb25zOiBUYXNrW10gPSBbXTtcbiAgICBmb3IgKGNvbnN0IHRhc2tDaHVuayBvZiB0YXNrQ2h1bmtzKSB7XG4gICAgICBjb25zdCBpbnB1dCA9IHtcbiAgICAgICAgdGFza3M6IHRhc2tDaHVuayxcbiAgICAgICAgY2x1c3RlcjogY2x1c3RlckFSTixcbiAgICAgIH07XG4gICAgICBjb25zdCBjb21tYW5kID0gbmV3IERlc2NyaWJlVGFza3NDb21tYW5kKGlucHV0KTtcbiAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4gICAgICBpZiAocmVzcG9uc2UgIT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRhc2tEZXNjcmlwdGlvbnMgPSB0YXNrRGVzY3JpcHRpb25zLmNvbmNhdChyZXNwb25zZS50YXNrcyEpO1xuICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gdGFza0Rlc2NyaXB0aW9ucztcbiAgfSBcbiAgcmV0dXJuIHVuZGVmaW5lZDtcbn07XG5cbi8vIGNvbXBhcmVzIGV2ZW50IGltYWdlIGRpZ2VzdCB3aXRoIHRhc2sgaW1hZ2UgZGlnZXN0XG5jb25zdCBjb21wYXJlRGlnZXN0cyA9IChcbiAgZXZlbnRJbWFnZURpZ2VzdDogc3RyaW5nLFxuICBpbWFnZURpZ2VzdDogc3RyaW5nXG4pOiBib29sZWFuID0+IHtcbiAgcmV0dXJuIGV2ZW50SW1hZ2VEaWdlc3QgPT09IGltYWdlRGlnZXN0O1xufTtcblxuLy8gZ2V0cyBhbGwgdGFzayBkZXNjcmlwdGlvbnMgZnJvbSBhbGwgY2x1c3RlcnNcbmNvbnN0IGdldEFsbFRhc2tEZXNjcmlwdGlvbnMgPSBhc3luYyAoY2x1c3RlckFSTnM6IHN0cmluZ1tdKTogUHJvbWlzZTxUYXNrW10+ID0+IHtcbiAgbGV0IHJldHVyblRhc2tMaXN0OiBUYXNrW10gPSBbXTtcbiAgZm9yIChjb25zdCBjbHVzdGVyIG9mIGNsdXN0ZXJBUk5zKSB7XG4gICAgY29uc3QgdGFza0lkcyA9IGF3YWl0IGxpc3RUYXNrc0Zyb21DbHVzdGVyQVJOKGNsdXN0ZXIpOyBcbiAgICBpZiAodGFza0lkcyAhPSB1bmRlZmluZWQpIHtcbiAgICAgIGNvbnN0IHRhc2tEZXNjcmlwdGlvbnMgPSBhd2FpdCBnZXRUYXNrRGVzY3JpcHRpb25zKGNsdXN0ZXIsIHRhc2tJZHMpOyBcbiAgICAgIGlmICh0YXNrRGVzY3JpcHRpb25zICE9IHVuZGVmaW5lZCkge1xuICAgICAgICByZXR1cm5UYXNrTGlzdCA9IHJldHVyblRhc2tMaXN0LmNvbmNhdCh0YXNrRGVzY3JpcHRpb25zISk7XG4gICAgICB9XG4gICAgfVxuICB9IHJldHVybiByZXR1cm5UYXNrTGlzdDtcbn1cblxuXG4vLyBtYWluIGxhbWJkYSBmdW5jdGlvblxuZXhwb3J0IGNvbnN0IGhhbmRsZXIgPSBhc3luYyBmdW5jdGlvbiAoXG4gIGV2ZW50OiBFdmVudEJyaWRnZUV2ZW50PHN0cmluZywgYW55PixcbiAgY29udGV4dDogQ29udGV4dCxcbiAgY2FsbGJhY2s6IENhbGxiYWNrXG4pIHtcbiAgY29uc3QgZXZlbnRJbWFnZUFSTjogc3RyaW5nID0gZXZlbnQucmVzb3VyY2VzWzBdO1xuICBjb25zdCBldmVudEltYWdlQVJORGlnZXN0SW5kZXggPSBldmVudEltYWdlQVJOLmxhc3RJbmRleE9mKFwiL3NoYTI1NjpcIik7XG4gIGNvbnN0IGV2ZW50SW1hZ2VEaWdlc3QgPSBldmVudEltYWdlQVJOLnNsaWNlKGV2ZW50SW1hZ2VBUk5EaWdlc3RJbmRleCArIDEpO1xuXG4gIHRyeSB7XG4gICAgY29uc3QgY2x1c3Rlckxpc3QgPSBhd2FpdCBnZXRMaXN0T2ZDbHVzdGVyQVJOKCk7IFxuICAgIGNvbnN0IGFsbFRhc2tzID0gYXdhaXQgZ2V0QWxsVGFza0Rlc2NyaXB0aW9ucyhjbHVzdGVyTGlzdCk7IFxuICAgIGlmIChhbGxUYXNrcyAhPSB1bmRlZmluZWQpIHtcbiAgICAgIGZvciAoY29uc3QgdGFzayBvZiBhbGxUYXNrcyEpIHtcbiAgICAgICAgaWYgKHRhc2suY29udGFpbmVycykge1xuICAgICAgICAgIGZvciAoY29uc3QgY29udGFpbmVyIG9mIHRhc2suY29udGFpbmVycyEpIHtcbiAgICAgICAgICAgIGlmIChjb21wYXJlRGlnZXN0cyhjb250YWluZXIuaW1hZ2VEaWdlc3QhLCBldmVudEltYWdlRGlnZXN0KSkge1xuICAgICAgICAgICAgICBjb25zb2xlLmxvZyhcbiAgICAgICAgICAgICAgICBgQ29udGFpbmVyOiAke2NvbnRhaW5lci5uYW1lfSBoYXMgYmVlbiBmb3VuZCB0byBoYXZlIGEgbmV3IHZ1bG5lcmFiaWxpdHkuIFRoZSBhc3NvY2lhdGVkIGltYWdlIGNhbiBiZSBmb3VuZCBoZXJlOiAke2NvbnRhaW5lci5pbWFnZX1gXG4gICAgICAgICAgICAgICk7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBjb25zb2xlLmxvZyhcbiAgICAgICAgICAgICAgICBgQ29udGFpbmVyOiAke2NvbnRhaW5lci5uYW1lfSBoYXMgbm90IGJlZW4gZm91bmQgdG8gaGF2ZSBhIG5ldyB2dWxuZXJhYmlsaXR5LiBUaGUgYXNzb2NpYXRlZCBpbWFnZSBjYW4gYmUgZm91bmQgaGVyZTogJHtjb250YWluZXIuaW1hZ2V9YFxuICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cbiAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICBjb25zb2xlLmVycm9yKGVycm9yKTtcbiAgfVxufTsiXX0=