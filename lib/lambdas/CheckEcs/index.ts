import { Callback, EventBridgeEvent, Context } from "aws-lambda";
import {
  ECSClient,
  ListClustersCommand,
  ListTasksCommand,
  DescribeTasksCommand,
  DescribeClustersCommand,
  Task,
} from "@aws-sdk/client-ecs";

const ecs = new ECSClient({});

// returns list of cluster ARN
const getListOfClusterARN = async (): Promise<string[]> => {
  let clusterList: string[] = [];
  let nextToken: string | undefined;

  const input = {};
  const command = new ListClustersCommand(input);
  do {
    const response = await ecs.send(command);
    if (response != undefined) {
      nextToken = response.nextToken;
      clusterList = clusterList.concat(response.clusterArns!);
    }
  } while (nextToken);
  return clusterList;
};

// returns list of ALL task ARN from specified cluster
const listTasksFromClusterARN = async (clusterName: string) => {
  let taskList: string[] = [];
  let nextToken: string | undefined;

  do {
    const input = {
      cluster: clusterName,
    };
    const command = new ListTasksCommand(input);
    const response = await ecs.send(command);
    if (response === undefined) {
      return undefined;
    } else {
      nextToken = response.nextToken;
      if (response.taskArns != undefined) {
        taskList = taskList.concat(response.taskArns);
      }
    }
  } while (nextToken);
  return taskList;
};

const chunkArray = (array: any[], chunkSize: number): any[][] => {
  const chunks: any[][] = [];
  let index = 0
  while (index < array.length) {
    chunks.push(array.slice(index, index + chunkSize));
    index += chunkSize;
  }
  return chunks;
}

const getTaskDescriptions = async (
  clusterARN: string,
  taskIdList: string[]
): Promise<Task[] | undefined> => {
  if (taskIdList.length <= 100) {
    const input = {
      tasks: taskIdList,
      cluster: clusterARN,
    };
    const command = new DescribeTasksCommand(input);
    const response = await ecs.send(command);
    if (response != undefined) {
      return response.tasks;
    }
  } else {
    const taskChunks = chunkArray(taskIdList, 100);
    let taskDescriptions: Task[] = [];
    for (const taskChunk of taskChunks) {
      const input = {
        tasks: taskChunk,
        cluster: clusterARN,
      };
      const command = new DescribeTasksCommand(input);
      const response = await ecs.send(command);
      if (response != undefined) {
        taskDescriptions = taskDescriptions.concat(response.tasks!);
      }
    }
    return taskDescriptions;
  } 
  return undefined;
};

// compares event image digest with task image digest
const compareDigests = (
  eventImageDigest: string,
  imageDigest: string
): boolean => {
  return eventImageDigest === imageDigest;
};

// gets all task descriptions from all clusters
const getAllTaskDescriptions = async (clusterARNs: string[]): Promise<Task[]> => {
  let returnTaskList: Task[] = [];
  for (const cluster of clusterARNs) {
    const taskIds = await listTasksFromClusterARN(cluster); 
    if (taskIds != undefined) {
      const taskDescriptions = await getTaskDescriptions(cluster, taskIds); 
      if (taskDescriptions != undefined) {
        returnTaskList = returnTaskList.concat(taskDescriptions!);
      }
    }
  } return returnTaskList;
}


// main lambda function
export const handler = async function (
  event: EventBridgeEvent<string, any>,
  context: Context,
  callback: Callback
) {
  const eventImageHash: string = event.detail.resources[0].details.awsEcrContainerImage.imageHash;
  // const eventImageARN: string = event.resources[0];
  // const eventImageARNDigestIndex = eventImageARN.lastIndexOf("/sha256:");
  // const eventImageDigest = eventImageARN.slice(eventImageARNDigestIndex + 1);

  try {
    const clusterList = await getListOfClusterARN(); 
    const allTasks = await getAllTaskDescriptions(clusterList); 
    if (allTasks != undefined) {
      for (const task of allTasks!) {
        if (task.containers) {
          for (const container of task.containers!) {
            if (compareDigests(container.imageDigest!, eventImageHash)) {
              console.log(
                `Container: ${container.name} has been found to have a new vulnerability, with image URI: ${container.image}`
              );
            } else {
              console.log(
                `Container: ${container.name} has not been found to have a new vulnerability. The image digest of the image with the new vulnerability is: ${eventImageHash}`
              );
            }
          }
        }
      }
    }
  } catch (error) {
    console.error(error);
  }
};