namespace Jail2Ban.WS.Models
{

    public class SuccessfuLogin
    {
        /// <summary>
        ///     ''' Authentication token to REST EndPoint
        ///     ''' </summary>
        ///     ''' <returns></returns>
        public string Token { get; set; } = "";
        /// <summary>
        ///     ''' This machine name
        ///     ''' </summary>
        ///     ''' <returns></returns>
        public string MachineName { get; set; } = "";
        /// <summary>
        ///     ''' Source login IP Address
        ///     ''' </summary>
        ///     ''' <returns></returns>
        public string IPAddress { get; set; } = "";
        /// <summary>
        ///     ''' Source login username
        ///     ''' </summary>
        ///     ''' <returns></returns>
        public string Username { get; set; } = "";
        /// <summary>
        ///     ''' Login date and time
        ///     ''' </summary>
        ///     ''' <returns></returns>
        public DateTime DateTime { get; set; }
        /// <summary>
        ///     ''' Extra details
        ///     ''' </summary>
        ///     ''' <returns></returns>
        public string Details { get; set; } = "";
    }

}
