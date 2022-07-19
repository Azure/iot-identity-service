using System.IO;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;

using Microsoft.Azure.Devices.Shared;               // For TwinCollection
using Microsoft.Azure.Devices.Provisioning.Service; // For TwinState

namespace DpsCustomAllocationFunctionProj
{
    public static class DpsCustomAllocation
    {
        [FunctionName("DpsCustomAllocation")]
        public static async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)]HttpRequest req,
        ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            // Get request body
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);

            log.LogInformation("Request.Body:...");
            log.LogInformation(requestBody);

            // Get the custom payload
            RequestPayload requestPayload = data?.deviceRuntimeContext?.payload?.ToObject<RequestPayload>();

            string message = "Uncaught error";
            bool fail = false;
            ResponseObj obj = new ResponseObj();

            if (requestPayload == null)
            {
                message = "Payload is not provided for the device.";
                log.LogInformation("Payload : NULL");
                fail = true;
            }
            else
            {
                string[] hubs = data?.linkedHubs?.ToObject<string[]>();

                // Must have hubs selected on the enrollment
                if (hubs == null)
                {
                    message = "No hub group defined for the enrollment.";
                    log.LogInformation("linkedHubs : NULL");
                    fail = true;
                }
                else
                {
                    if (requestPayload.modelId == null)
                    {
                        message = "Payload does not contain a 'modelId' field.";
                        log.LogInformation("modelId: NULL");
                        fail = true;
                    } 
                    else if (requestPayload.modelId.Contains("foo"))
                    {
                        // Find the "foo" IoT hub configured on the enrollment
                        foreach(string hubString in hubs)
                        {
                            if (hubString.Contains("foo"))
                                obj.iotHubHostName = hubString;
                        }

                        if (obj.iotHubHostName == null)
                        {
                            message = "No 'foo' devices hub found for the enrollment.";
                            log.LogInformation(message);
                            fail = true;
                        }
                        else
                        {
                            // TODO: Consider setting obj.initialTwin

                            // Set a response payload with a "Succes" message and copy of request payoad
                            ResponsePayload responsePayload = new ResponsePayload();
                            responsePayload.message = "Success";
                            responsePayload.requestPayload = requestPayload;
                            obj.payload = responsePayload;
                        }
                    } 
                    else
                    {
                        fail = true;
                        message = "Unrecognized device registration.";
                        log.LogInformation("Unknown device registration");
                    }
                }
            }

            log.LogInformation("\nResponse");
            log.LogInformation((obj.iotHubHostName != null) ? JsonConvert.SerializeObject(obj) : message);

            return (fail)
                ? new BadRequestObjectResult(message) 
                : (ActionResult)new OkObjectResult(obj);
        }
    }

    public class ResponseObj
    {
        public string iotHubHostName {get; set;}
        public TwinState initialTwin {get; set;}
        public ResponsePayload payload {get; set;}
    }

    public class RequestPayload
    {
        public string modelId {get; set;}
    }

    public class ResponsePayload
    {
        public string message {get; set;}
        public RequestPayload requestPayload {get; set;}
    }
}
