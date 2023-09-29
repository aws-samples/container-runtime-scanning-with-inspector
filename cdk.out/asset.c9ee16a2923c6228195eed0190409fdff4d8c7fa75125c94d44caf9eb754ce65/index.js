"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const client_ecs_1 = require("@aws-sdk/client-ecs");
const REGION = "us-east-1";
const ecs = new client_ecs_1.ECSClient({ region: REGION });
async function getListOfClusterARN() {
    const input = {};
    const command = new client_ecs_1.ListClustersCommand(input);
    const response = await ecs.send(command);
    // console.log(`
    //     #############
    //     list of clusters:  ${JSON.stringify(response)}
    //     #############
    // `)
    if (response != undefined) {
        return response.clusterArns;
    }
    return [];
}
async function listTasksFromClusterARN(clusterName) {
    const input = {
        cluster: clusterName
    };
    const command = new client_ecs_1.ListTasksCommand(input);
    const response = await ecs.send(command);
    console.log(`
    #############
    list tasks from cluster arn: ${response.taskArns} 
    #############
    `);
    return response.taskArns;
}
function formatTaskName(taskARN) {
    const indexOfLastSlash = taskARN.lastIndexOf("/");
    const taskName = taskARN.substring(indexOfLastSlash + 1);
    return taskName;
}
async function getVulnerableDigestsPerARN(clusterARN) {
    const taskList = await listTasksFromClusterARN(clusterARN);
    let vulnerableDigests = {};
    if (taskList != undefined) {
        const taskIdList = taskList.map((task) => formatTaskName(task));
        const input = {
            tasks: taskIdList,
            cluster: clusterARN
        };
        const command = new client_ecs_1.DescribeTasksCommand(input);
        const response = await ecs.send(command);
        const listOfTasksFromResponse = response.tasks;
        if (listOfTasksFromResponse != undefined) {
            // need to loop through each task, then loop through each container
            listOfTasksFromResponse.forEach(task => {
                for (let n = 0; n < task.containers.length; n++) {
                    if (task.containers[n].taskArn in vulnerableDigests) {
                        // if the taskArn is already in the dictionary, add the imageDigest to the list
                        vulnerableDigests[task.containers[n].taskArn].push(task.containers[n].imageDigest);
                    }
                    else {
                        // if the taskArn is not in the dictionary, add the imageDigest to the dictionary
                        vulnerableDigests[task.containers[n].taskArn] = [task.containers[n].imageDigest];
                    }
                }
            });
        }
        return vulnerableDigests;
    }
    return undefined;
}
function compareDigests(eventImageDigest, imageDigest) {
    return eventImageDigest === imageDigest;
}
// more logs increase value, separate into individual logs
// add a log of image freshness , comment above it as a reminder of where i put in code to reference/debug back
function printLogMessage(vulnerableDigest, eventImgDigest) {
    if (vulnerableDigest == undefined || Object.keys(vulnerableDigest).length === 0) {
        console.log(`No ECS tasks with vulnerable image ${eventImgDigest} found.`);
    }
    else {
        for (const vuln of vulnerableDigest) {
            vuln.forEach((digest) => {
                if (compareDigests(digest, eventImgDigest)) {
                    console.log(`ECS task with vulnerable image ${eventImgDigest} found: ${vuln}`);
                    console.log(`${digest}`);
                }
            });
        }
    }
}
exports.handler = async function (event, context, callback) {
    // console.log(`
    // ###############
    // ${JSON.stringify(event)}
    // ###############
    // `)
    // need to validate over time as there are several scan status formats https://docs.aws.amazon.com/inspector/latest/user/eventbridge-integration.html
    // const eventImageFreshness: string = event.detail.scanStatus;
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
    clusterList.forEach(cluster => {
        const vulnResources = getVulnerableDigestsPerARN(cluster);
        printLogMessage(vulnResources, eventImageDigest);
    });
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyJpbmRleC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOztBQUdBLG9EQUE2RztBQUU3RyxNQUFNLE1BQU0sR0FBRyxXQUFXLENBQUE7QUFDMUIsTUFBTSxHQUFHLEdBQUcsSUFBSSxzQkFBUyxDQUFDLEVBQUUsTUFBTSxFQUFFLE1BQU0sRUFBRSxDQUFDLENBQUM7QUFFOUMsS0FBSyxVQUFVLG1CQUFtQjtJQUM5QixNQUFNLEtBQUssR0FBRyxFQUFFLENBQUE7SUFDaEIsTUFBTSxPQUFPLEdBQUcsSUFBSSxnQ0FBbUIsQ0FBQyxLQUFLLENBQUMsQ0FBQztJQUMvQyxNQUFNLFFBQVEsR0FBRyxNQUFNLEdBQUcsQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUM7SUFDekMsZ0JBQWdCO0lBQ2hCLG9CQUFvQjtJQUNwQixxREFBcUQ7SUFDckQsb0JBQW9CO0lBQ3BCLEtBQUs7SUFDTCxJQUFJLFFBQVEsSUFBSSxTQUFTLEVBQUU7UUFDdkIsT0FBTyxRQUFRLENBQUMsV0FBWSxDQUFDO0tBQ2hDO0lBQ0QsT0FBTyxFQUFFLENBQUM7QUFDZCxDQUFDO0FBRUQsS0FBSyxVQUFVLHVCQUF1QixDQUFDLFdBQW1CO0lBQ3RELE1BQU0sS0FBSyxHQUFHO1FBQ1YsT0FBTyxFQUFFLFdBQVc7S0FDdkIsQ0FBQTtJQUNELE1BQU0sT0FBTyxHQUFHLElBQUksNkJBQWdCLENBQUMsS0FBSyxDQUFDLENBQUM7SUFDNUMsTUFBTSxRQUFRLEdBQUcsTUFBTSxHQUFHLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxDQUFDO0lBQ3pDLE9BQU8sQ0FBQyxHQUFHLENBQUM7O21DQUVtQixRQUFRLENBQUMsUUFBUTs7S0FFL0MsQ0FBQyxDQUFBO0lBQ0YsT0FBTyxRQUFRLENBQUMsUUFBUSxDQUFDO0FBQzdCLENBQUM7QUFFRCxTQUFTLGNBQWMsQ0FBQyxPQUFlO0lBQ25DLE1BQU0sZ0JBQWdCLEdBQUcsT0FBTyxDQUFD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Q0FBQyxDQUFDLENBQUE7U0FDTDtLQUNKO0FBQ0wsQ0FBQztBQUdELE9BQU8sQ0FBQyxPQUFPLEdBQUcsS0FBSyxXQUNuQixLQUFvQyxFQUNwQyxPQUFnQixFQUNoQixRQUFrQjtJQUVkLGdCQUFnQjtJQUNoQixrQkFBa0I7SUFDbEIsMkJBQTJCO0lBQzNCLGtCQUFrQjtJQUNsQixLQUFLO0lBQ0wscUpBQXFKO0lBQ3JKLCtEQUErRDtJQUMvRCxNQUFNLGFBQWEsR0FBVyxLQUFLLENBQUMsU0FBUyxDQUFDLENBQUMsQ0FBQyxDQUFDO0lBQ2pELDBGQUEwRjtJQUMxRixNQUFNLHdCQUF3QixHQUFHLGFBQWEsQ0FBQyxXQUFXLENBQUMsVUFBVSxDQUFDLENBQUM7SUFDdkUsTUFBTSxnQkFBZ0IsR0FBRyxhQUFhLENBQUMsS0FBSyxDQUFDLHdCQUF3QixHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUMsMENBQTBDO0lBQ3RILGdCQUFnQjtJQUNoQixrQkFBa0I7SUFDbEIsc0RBQXNEO0lBQ3RELGtCQUFrQjtJQUNsQixNQUFNO0lBRU4sTUFBTSxXQUFXLEdBQUcsTUFBTSxtQkFBbUIsRUFBRSxDQUFDO0lBQ2hELFdBQVcsQ0FBQyxPQUFPLENBQUMsT0FBTyxDQUFDLEVBQUU7UUFDMUIsTUFBTSxhQUFhLEdBQUcsMEJBQTBCLENBQUMsT0FBTyxDQUFDLENBQUM7UUFDMUQsZUFBZSxDQUFDLGFBQWEsRUFBRSxnQkFBZ0IsQ0FBQyxDQUFDO0lBQ3JELENBQUMsQ0FBQyxDQUFBO0FBRU4sQ0FBQyxDQUFBIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0ICogYXMgQVdTIGZyb20gXCJhd3Mtc2RrXCI7XG5pbXBvcnQgeyBDYWxsYmFjaywgRXZlbnRCcmlkZ2VFdmVudCwgQ29udGV4dCB9IGZyb20gXCJhd3MtbGFtYmRhXCI7IFxuaW1wb3J0IHsgRGV0YWlscyB9IGZyb20gXCJhd3Mtc2RrL2NsaWVudHMvZGF0YWV4Y2hhbmdlXCI7XG5pbXBvcnQgeyBFQ1NDbGllbnQsIExpc3RDbHVzdGVyc0NvbW1hbmQsIExpc3RUYXNrc0NvbW1hbmQsIERlc2NyaWJlVGFza3NDb21tYW5kIH0gZnJvbSBcIkBhd3Mtc2RrL2NsaWVudC1lY3NcIjtcblxuY29uc3QgUkVHSU9OID0gXCJ1cy1lYXN0LTFcIlxuY29uc3QgZWNzID0gbmV3IEVDU0NsaWVudCh7IHJlZ2lvbjogUkVHSU9OIH0pO1xuXG5hc3luYyBmdW5jdGlvbiBnZXRMaXN0T2ZDbHVzdGVyQVJOKCk6IFByb21pc2U8c3RyaW5nW10+IHtcbiAgICBjb25zdCBpbnB1dCA9IHt9IFxuICAgIGNvbnN0IGNvbW1hbmQgPSBuZXcgTGlzdENsdXN0ZXJzQ29tbWFuZChpbnB1dCk7XG4gICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBlY3Muc2VuZChjb21tYW5kKTtcbiAgICAvLyBjb25zb2xlLmxvZyhgXG4gICAgLy8gICAgICMjIyMjIyMjIyMjIyNcbiAgICAvLyAgICAgbGlzdCBvZiBjbHVzdGVyczogICR7SlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpfVxuICAgIC8vICAgICAjIyMjIyMjIyMjIyMjXG4gICAgLy8gYClcbiAgICBpZiAocmVzcG9uc2UgIT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHJldHVybiByZXNwb25zZS5jbHVzdGVyQXJucyE7XG4gICAgfVxuICAgIHJldHVybiBbXTtcbn1cblxuYXN5bmMgZnVuY3Rpb24gbGlzdFRhc2tzRnJvbUNsdXN0ZXJBUk4oY2x1c3Rlck5hbWU6IHN0cmluZykge1xuICAgIGNvbnN0IGlucHV0ID0ge1xuICAgICAgICBjbHVzdGVyOiBjbHVzdGVyTmFtZVxuICAgIH1cbiAgICBjb25zdCBjb21tYW5kID0gbmV3IExpc3RUYXNrc0NvbW1hbmQoaW5wdXQpO1xuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZWNzLnNlbmQoY29tbWFuZCk7XG4gICAgY29uc29sZS5sb2coYFxuICAgICMjIyMjIyMjIyMjIyNcbiAgICBsaXN0IHRhc2tzIGZyb20gY2x1c3RlciBhcm46ICR7cmVzcG9uc2UudGFza0FybnN9IFxuICAgICMjIyMjIyMjIyMjIyNcbiAgICBgKVxuICAgIHJldHVybiByZXNwb25zZS50YXNrQXJucztcbn1cblxuZnVuY3Rpb24gZm9ybWF0VGFza05hbWUodGFza0FSTjogc3RyaW5nKTogc3RyaW5nIHtcbiAgICBjb25zdCBpbmRleE9mTGFzdFNsYXNoID0gdGFza0FSTi5sYXN0SW5kZXhPZihcIi9cIik7XG4gICAgY29uc3QgdGFza05hbWUgPSB0YXNrQVJOLnN1YnN0cmluZyhpbmRleE9mTGFzdFNsYXNoICsgMSk7XG4gICAgcmV0dXJuIHRhc2tOYW1lO1xufVxuXG5hc3luYyBmdW5jdGlvbiBnZXRWdWxuZXJhYmxlRGlnZXN0c1BlckFSTihjbHVzdGVyQVJOOiBzdHJpbmcpOiBQcm9taXNlPGFueT4gIHtcbiAgICBjb25zdCB0YXNrTGlzdCA9IGF3YWl0IGxpc3RUYXNrc0Zyb21DbHVzdGVyQVJOKGNsdXN0ZXJBUk4pO1xuICAgIGxldCB2dWxuZXJhYmxlRGlnZXN0czogeyBba2V5OiBzdHJpbmddOiBzdHJpbmdbXSB9ID0ge307XG4gICAgaWYgKHRhc2tMaXN0ICE9IHVuZGVmaW5lZCkge1xuICAgICAgICBjb25zdCB0YXNrSWRMaXN0ID0gdGFza0xpc3QubWFwKCh0YXNrOiBzdHJpbmcpID0+IGZvcm1hdFRhc2tOYW1lKHRhc2spKTtcbiAgICAgICAgY29uc3QgaW5wdXQgPSB7XG4gICAgICAgICAgICB0YXNrczogdGFza0lkTGlzdCxcbiAgICAgICAgICAgIGNsdXN0ZXI6IGNsdXN0ZXJBUk5cbiAgICAgICAgfVxuICAgICAgICBjb25zdCBjb21tYW5kID0gbmV3IERlc2NyaWJlVGFza3NDb21tYW5kKGlucHV0KTtcbiAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBlY3Muc2VuZChjb21tYW5kKTtcbiAgICAgICAgY29uc3QgbGlzdE9mVGFza3NGcm9tUmVzcG9uc2UgPSByZXNwb25zZS50YXNrcztcbiAgICAgICAgaWYgKGxpc3RPZlRhc2tzRnJvbVJlc3BvbnNlICE9ICB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgIC8vIG5lZWQgdG8gbG9vcCB0aHJvdWdoIGVhY2ggdGFzaywgdGhlbiBsb29wIHRocm91Z2ggZWFjaCBjb250YWluZXJcbiAgICAgICAgICAgIGxpc3RPZlRhc2tzRnJvbVJlc3BvbnNlLmZvckVhY2godGFzayA9PiB7XG4gICAgICAgICAgICAgICAgZm9yIChsZXQgbiA9IDA7IG4gPCB0YXNrLmNvbnRhaW5lcnMhLmxlbmd0aDsgbisrKSB7XG4gICAgICAgICAgICAgICAgICAgIGlmICh0YXNrLmNvbnRhaW5lcnMhW25dLnRhc2tBcm4hIGluIHZ1bG5lcmFibGVEaWdlc3RzKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBpZiB0aGUgdGFza0FybiBpcyBhbHJlYWR5IGluIHRoZSBkaWN0aW9uYXJ5LCBhZGQgdGhlIGltYWdlRGlnZXN0IHRvIHRoZSBsaXN0XG4gICAgICAgICAgICAgICAgICAgICAgICB2dWxuZXJhYmxlRGlnZXN0c1t0YXNrLmNvbnRhaW5lcnMhW25dLnRhc2tBcm4hXS5wdXNoKHRhc2suY29udGFpbmVycyFbbl0uaW1hZ2VEaWdlc3QhKTtcbiAgICAgICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIGlmIHRoZSB0YXNrQXJuIGlzIG5vdCBpbiB0aGUgZGljdGlvbmFyeSwgYWRkIHRoZSBpbWFnZURpZ2VzdCB0byB0aGUgZGljdGlvbmFyeVxuICAgICAgICAgICAgICAgICAgICAgICAgdnVsbmVyYWJsZURpZ2VzdHNbdGFzay5jb250YWluZXJzIVtuXS50YXNrQXJuIV0gPSBbdGFzay5jb250YWluZXJzIVtuXS5pbWFnZURpZ2VzdCFdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSlcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gdnVsbmVyYWJsZURpZ2VzdHM7XG4gICAgfVxuICAgIHJldHVybiB1bmRlZmluZWQ7XG59XG5cbmZ1bmN0aW9uIGNvbXBhcmVEaWdlc3RzKGV2ZW50SW1hZ2VEaWdlc3Q6IHN0cmluZywgaW1hZ2VEaWdlc3Q6IHN0cmluZyk6IGJvb2xlYW4ge1xuICAgIHJldHVybiBldmVudEltYWdlRGlnZXN0ID09PSBpbWFnZURpZ2VzdDtcbn1cblxuLy8gbW9yZSBsb2dzIGluY3JlYXNlIHZhbHVlLCBzZXBhcmF0ZSBpbnRvIGluZGl2aWR1YWwgbG9nc1xuLy8gYWRkIGEgbG9nIG9mIGltYWdlIGZyZXNobmVzcyAsIGNvbW1lbnQgYWJvdmUgaXQgYXMgYSByZW1pbmRlciBvZiB3aGVyZSBpIHB1dCBpbiBjb2RlIHRvIHJlZmVyZW5jZS9kZWJ1ZyBiYWNrXG5mdW5jdGlvbiBwcmludExvZ01lc3NhZ2UodnVsbmVyYWJsZURpZ2VzdDogYW55ICwgZXZlbnRJbWdEaWdlc3Q6IHN0cmluZykge1xuICAgIGlmICh2dWxuZXJhYmxlRGlnZXN0ID09IHVuZGVmaW5lZCB8fCBPYmplY3Qua2V5cyh2dWxuZXJhYmxlRGlnZXN0KS5sZW5ndGggPT09IDApIHtcbiAgICAgICAgY29uc29sZS5sb2coYE5vIEVDUyB0YXNrcyB3aXRoIHZ1bG5lcmFibGUgaW1hZ2UgJHtldmVudEltZ0RpZ2VzdH0gZm91bmQuYCk7XG4gICAgfSBlbHNlIHtcbiAgICAgICAgZm9yIChjb25zdCB2dWxuIG9mIHZ1bG5lcmFibGVEaWdlc3QpIHtcbiAgICAgICAgICAgIHZ1bG4uZm9yRWFjaCgoZGlnZXN0OiBzdHJpbmcpID0+IHtcbiAgICAgICAgICAgICAgICBpZiAoY29tcGFyZURpZ2VzdHMoZGlnZXN0LCBldmVudEltZ0RpZ2VzdCkpe1xuICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZyhgRUNTIHRhc2sgd2l0aCB2dWxuZXJhYmxlIGltYWdlICR7ZXZlbnRJbWdEaWdlc3R9IGZvdW5kOiAke3Z1bG59YCk7XG4gICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKGAke2RpZ2VzdH1gKVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pXG4gICAgICAgIH1cbiAgICB9XG59XG5cblxuZXhwb3J0cy5oYW5kbGVyID0gYXN5bmMgZnVuY3Rpb24oXG4gICAgZXZlbnQ6IEV2ZW50QnJpZGdlRXZlbnQ8c3RyaW5nLCBhbnk+LFxuICAgIGNvbnRleHQ6IENvbnRleHQsXG4gICAgY2FsbGJhY2s6IENhbGxiYWNrLFxuICAgICkge1xuICAgICAgICAvLyBjb25zb2xlLmxvZyhgXG4gICAgICAgIC8vICMjIyMjIyMjIyMjIyMjI1xuICAgICAgICAvLyAke0pTT04uc3RyaW5naWZ5KGV2ZW50KX1cbiAgICAgICAgLy8gIyMjIyMjIyMjIyMjIyMjXG4gICAgICAgIC8vIGApXG4gICAgICAgIC8vIG5lZWQgdG8gdmFsaWRhdGUgb3ZlciB0aW1lIGFzIHRoZXJlIGFyZSBzZXZlcmFsIHNjYW4gc3RhdHVzIGZvcm1hdHMgaHR0cHM6Ly9kb2NzLmF3cy5hbWF6b24uY29tL2luc3BlY3Rvci9sYXRlc3QvdXNlci9ldmVudGJyaWRnZS1pbnRlZ3JhdGlvbi5odG1sXG4gICAgICAgIC8vIGNvbnN0IGV2ZW50SW1hZ2VGcmVzaG5lc3M6IHN0cmluZyA9IGV2ZW50LmRldGFpbC5zY2FuU3RhdHVzO1xuICAgICAgICBjb25zdCBldmVudEltYWdlQVJOOiBzdHJpbmcgPSBldmVudC5yZXNvdXJjZXNbMF07XG4gICAgICAgIC8vIGNvbnN0IGV2ZW50SW1hZ2VEaWdlc3Q6IHN0cmluZyA9IGV2ZW50LmRldGFpbC5yZXNvdXJjZXMuYXdzRWNyQ29udGFpbmVySW1hZ2UuaW1hZ2VIYXNoIFxuICAgICAgICBjb25zdCBldmVudEltYWdlQVJORGlnZXN0SW5kZXggPSBldmVudEltYWdlQVJOLmxhc3RJbmRleE9mKFwiL3NoYTI1NjpcIik7XG4gICAgICAgIGNvbnN0IGV2ZW50SW1hZ2VEaWdlc3QgPSBldmVudEltYWdlQVJOLnNsaWNlKGV2ZW50SW1hZ2VBUk5EaWdlc3RJbmRleCArIDEpOyAvLyBhZGRlZCArIDEgdG8gcmVtb3ZlIHRoZSAvIGluIHRoZSBzdHJpbmdcbiAgICAgICAgLy8gY29uc29sZS5sb2coYFxuICAgICAgICAvLyAjIyMjIyMjIyMjIyMjIyNcbiAgICAgICAgLy8gVGhpcyBpcyB0aGUgZXZlbnQgaW1hZ2UgZGlnZXN0OiAke2V2ZW50SW1hZ2VEaWdlc3R9XG4gICAgICAgIC8vICMjIyMjIyMjIyMjIyMjI1xuICAgICAgICAvLyBgKTtcbiAgICAgICAgXG4gICAgICAgIGNvbnN0IGNsdXN0ZXJMaXN0ID0gYXdhaXQgZ2V0TGlzdE9mQ2x1c3RlckFSTigpO1xuICAgICAgICBjbHVzdGVyTGlzdC5mb3JFYWNoKGNsdXN0ZXIgPT4ge1xuICAgICAgICAgICAgY29uc3QgdnVsblJlc291cmNlcyA9IGdldFZ1bG5lcmFibGVEaWdlc3RzUGVyQVJOKGNsdXN0ZXIpO1xuICAgICAgICAgICAgcHJpbnRMb2dNZXNzYWdlKHZ1bG5SZXNvdXJjZXMsIGV2ZW50SW1hZ2VEaWdlc3QpO1xuICAgICAgICB9KVxuICAgICAgICBcbiAgICB9XG4iXX0=