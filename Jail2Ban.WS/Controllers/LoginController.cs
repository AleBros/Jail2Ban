using Jail2Ban.WS.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Text.Json;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Jail2Ban.WS.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        // POST api/<LoginController>
        [HttpPost]
        public void Post([FromBody] JsonDocument value)
        {
            //try
            //{
                var log = JsonSerializer.Deserialize<SuccessfuLogin>(JsonSerializer.Serialize( value));

                if (log != null && log.Token == "bbTestToken")
                {
                    IConfigurationRoot configuration = new ConfigurationBuilder()
                    .SetBasePath(AppDomain.CurrentDomain.BaseDirectory)
                    .AddJsonFile("appsettings.json")
                    .Build();

                var cn = new System.Data.SqlClient.SqlConnection(configuration.GetConnectionString("Log"));
                    var cmd = new System.Data.SqlClient.SqlCommand(@"
                            insert into LoginLog
                            (MachineName, IPAddress, Username, DateTime, Details)
                            values
                            (@MachineName, @IPAddress, @Username, @DateTime, @Details)
                            ",cn); 
                cn.Open();
                    cmd.Parameters.AddWithValue("MachineName", log.MachineName);
                    cmd.Parameters.AddWithValue("IPAddress", log.IPAddress);
                    cmd.Parameters.AddWithValue("Username", log.Username);
                    cmd.Parameters.AddWithValue("DateTime", log.DateTime);
                    cmd.Parameters.AddWithValue("Details", log.Details);
                    cmd.Connection.Open();
                    cmd.ExecuteNonQuery();
                    cmd.Connection.Close();

                    cmd.Dispose();
                }
            //}
            //catch (Exception e)
            //{
            //    var a = e;  
            //}


        }
    }
}
