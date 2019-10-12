Imports NetFwTypeLib
Imports System.Net
Imports System.Linq
Imports System
Imports System.Diagnostics
Imports System.Threading
Imports System.Diagnostics.Eventing.Reader
Imports Newtonsoft.Json

Module MainModule

    Dim Cfg As New ConfigurationModel
    Dim ConfigurationFileName = "Config.json"

    Dim StartTime As DateTime

    'DiscoveryMode - Checks for an event and lists its properties
    Dim DiscoveryMode = False
    Dim DiscoveryLog = ""
    Dim DiscoveryEventId = 0
    Dim DiscoveryRegex = ""

    Dim FullLog = False
    Dim ConsoleHeight = 50

    Dim IISDefaultWebSiteLogFile As String = "C:\inetpub\logs\LogFiles\W3SVC1"

    Dim BanList As New List(Of String)

    Sub Main()

        Console.WriteLine($"Jail2Ban loading...")
        StartTime = Now

        For Each argument In My.Application.CommandLineArgs
            Dim arg = ""
            Dim val = ""
            If argument.Contains(":") Then
                arg = argument.Split(":")(0)
                val = argument.Split(":")(1)
                If arg.StartsWith("-") Or arg.StartsWith("/") Then
                    arg = arg.Substring(1)
                End If
            End If
            Select Case arg.ToLower
                Case "configuration"
                    ConfigurationFileName = val
                Case "discover", "discovery", "discoverymode"
                    Boolean.TryParse(val, DiscoveryMode)
                Case "log"
                    DiscoveryLog = val
                Case "eventid", "id"
                    If IsNumeric(val) Then DiscoveryEventId = CInt(val)
                Case "regex"
                    DiscoveryRegex = val
                Case "full"
                    FullLog = True
            End Select
        Next

        If Not IO.Directory.Exists(IISDefaultWebSiteLogFile) Then IISDefaultWebSiteLogFile = ""

        If DiscoveryMode Then
            Discover()
        Else
            Start()
        End If

    End Sub

    Private Sub Start()

        If IO.File.Exists(ConfigurationFileName) Then
            'Load configuration
            Try
                Cfg = JsonConvert.DeserializeObject(Of ConfigurationModel)(IO.File.ReadAllText(ConfigurationFileName))
            Catch ex As Exception
                Console.ForegroundColor = ConsoleColor.Red
                Console.WriteLine($"Loading configuration file {ConfigurationFileName} failed.")
                Console.WriteLine(ex.Message)
                Console.ResetColor()
            End Try
        Else
            'Save the first configuration file
            IO.File.WriteAllText(ConfigurationFileName, JsonConvert.SerializeObject(Cfg))
        End If

        'Populate the WhiteList with machine address
        Console.ForegroundColor = ConsoleColor.White
        Console.WriteLine("Populating Whitelist with this machine addresses:")
        Console.ResetColor()
        Cfg.WhiteList.Add("127.0.0.1")
        Console.WriteLine(" - 127.0.0.1")
        For Each sl In (From x In Dns.GetHostEntry(Dns.GetHostName).AddressList)
            Cfg.WhiteList.Add(sl.ToString)
            Console.WriteLine($" - {sl.ToString}")
        Next
        Console.WriteLine("")

        'Enable/Disable IIS Log Search for php
        If Not Cfg.SearchForIISLogPhp404 Then IISDefaultWebSiteLogFile = ""

        'Load History
        Console.WriteLine("Loading history file...")
        Dim JailTable As New JailDataSet.JailDataTable
        Dim LogTable As New JailDataSet.LogDataTable
        If IO.File.Exists(Cfg.JailFileName) Then
            JailTable = JsonConvert.DeserializeObject(Of JailDataSet.JailDataTable)(IO.File.ReadAllText(Cfg.JailFileName))
        End If

        'Lock IPs basing on the history file (in case you need to recreate the block rule loading another computer history)
        For Each row In JailTable.Where(Function(x) Not BanList.Contains(x.IP) AndAlso (x.Banned Or (x.Count >= Cfg.CheckCount And DateDiff(DateInterval.Minute, x.First, x.Last) < Cfg.CheckMinutes) Or x.Count > Cfg.OverallThreshold))
            If Not BanList.Contains(row.IP) Then
                row.Banned = MainModule.Jail(row.IP)
                If row.Banned Then BanList.Add(row.IP)
            End If
        Next
        Console.WriteLine("")

        Console.WriteLine("Application starts in 5 seconds.")
        Threading.Thread.Sleep(5000)

        Dim EventsToCheck = New JailDataSet.EventToCheckDataTable
        EventsToCheck.AddEventToCheckRow("Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", 140, 0, Nothing)
        EventsToCheck.AddEventToCheckRow("Security", 4625, 19, Nothing)
        EventsToCheck.AddEventToCheckRow("Application", 18456, 2, "\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
        EventsToCheck.AddEventToCheckRow("Application", 17806, 4, "\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")

        'Starts the infinite loop
        While True
            Dim LastQueryTime As Date?
            Dim StartQueryTime = Now
            For Each etcRow In EventsToCheck
                Console.WriteLine()
                Console.WriteLine("Reading " & etcRow.Log & "...")
                Dim query As EventLogQuery
                Try
                    'If it is the first time I'll check the entair registry
                    If Not LastQueryTime.HasValue Then
                        query = New EventLogQuery(etcRow.Log, PathType.LogName)
                    Else
                        query = New EventLogQuery(etcRow.Log, PathType.LogName, $"*[System[TimeCreated[@SystemTime >= '{LastQueryTime.Value.ToUniversalTime.ToString("o")}']]]")
                    End If

                Catch ex As Exception
                    Console.ForegroundColor = ConsoleColor.Red
                    Console.WriteLine(etcRow.Log & ": " & ex.Message)
                    Console.ResetColor()
                    GoTo NextEventType
                End Try

                Dim CurrentDate = Date.MinValue
                Dim EventCountPerDay = 0

                Using reader = New EventLogReader(query)
                    Dim e = reader.ReadEvent()
                    While Not e Is Nothing
                        If e.Id = etcRow.EventID Then
                            Dim ip = e.Properties(etcRow.PropertyIndex).Value
                            If Not etcRow.IsRegexNull AndAlso etcRow.Regex <> "" Then
                                ip = GetResult(ip, etcRow.Regex)
                            End If
                            If ip <> "" Then
                                Dim jRow = JailTable.FindByIP(ip)
                                Dim lRow = LogTable.FindByEventIDLogNameDateTimeIP(e.Id, etcRow.Log, e.TimeCreated, ip)
                                If jRow Is Nothing Then jRow = JailTable.AddJailRow(ip, 1, e.TimeCreated, e.TimeCreated, False)
                                If lRow Is Nothing Then lRow = LogTable.AddLogRow(ip, e.TimeCreated, etcRow.Log, e.Id)

                                If jRow.Last < e.TimeCreated Then
                                    jRow.Count += 1
                                    jRow.Last = e.TimeCreated
                                    'Check how many fail log are from the same ip in the previous CheckMinutes, if there are at least the CheckCount the IP will be banned                                                                        
                                    If Not jRow.Banned AndAlso LogTable.Where(Function(x) x.IP = ip And x.DateTime >= jRow.Last.AddMinutes(-Cfg.CheckMinutes)).Count >= Cfg.CheckCount Then
                                        jRow.Banned = MainModule.Jail(ip)
                                    End If
                                End If
                                'Check if the same ip has reached the overall threshold limit
                                If jRow.Count > Cfg.OverallThreshold And Not jRow.Banned Then
                                    jRow.Banned = MainModule.Jail(ip)
                                End If
                            End If

                            If CurrentDate <> e.TimeCreated.Value.Date Then
                                'First line for the current date
                                Console.SetCursorPosition(0, Console.CursorTop)
                                CurrentDate = e.TimeCreated.Value.Date
                                Console.WriteLine()
                                Console.Write(CurrentDate.ToShortDateString & " ")
                                EventCountPerDay = 0
                            End If
                            EventCountPerDay += 1
                            Console.SetCursorPosition(12, Console.CursorTop)
                            Console.Write(EventCountPerDay)

                        End If

                        'Need to free memory
                        e.Dispose()
                        e = Nothing

                        e = reader.ReadEvent()

                    End While
                End Using
NextEventType:
                query = Nothing
            Next

            Console.WriteLine()
            Console.WriteLine("Reading IIS Log Files...")
            If IISDefaultWebSiteLogFile <> "" Then
                Dim TodayLog = IO.Path.Combine(IISDefaultWebSiteLogFile, $"u_ex{Now.ToString("yyMMdd")}.log")
                If IO.File.Exists(TodayLog) Then
                    'Opening the log file in ReadOnly mode
                    Dim fs = New IO.FileStream(TodayLog, IO.FileMode.Open, IO.FileAccess.Read, IO.FileShare.ReadWrite)
                    Dim sr = New IO.StreamReader(fs)
                    Dim content = sr.ReadToEnd()

                    Dim LogReader As New IO.StringReader(content)
                    Dim LogEntry = LogReader.ReadLine
                    'Getting the fields index inside the log file
                    Dim cs_ip_index = -1
                    Dim date_index = -1
                    Dim time_index = -1

                    While LogEntry IsNot Nothing
                        'Getting the fields index inside the log file
                        If LogEntry.StartsWith("#Fields:") Then
                            Dim fields = LogEntry.Replace("#Fields: ", "").Split(" ")
                            Dim i = 0
                            For i = 0 To UBound(fields)
                                Select Case fields(i)
                                    Case "c-ip"
                                        cs_ip_index = i
                                    Case "date"
                                        date_index = i
                                    Case "time"
                                        time_index = i
                                End Select
                            Next
                        End If
                        'Reading the log entry
                        If cs_ip_index >= 0 AndAlso LogEntry.ToLower.Contains("404") AndAlso
                            (LogEntry.ToLower.Contains(".php") OrElse LogEntry.ToLower.Contains("phpmyadmin") OrElse LogEntry.ToLower.Contains("phpadmin")) Then
                            Dim Fields = LogEntry.Split(" ")
                            Dim ip = Fields(cs_ip_index)
                            Dim LogTime As DateTime = Now
                            Date.TryParse(Fields(date_index) & " " & Fields(time_index), LogTime)

                            If ip <> "" AndAlso Not BanList.Contains(ip) Then
                                Dim jRow = JailTable.FindByIP(ip)
                                If jRow Is Nothing Then jRow = JailTable.AddJailRow(ip, 1, LogTime, LogTime, False)

                                If jRow.Last < LogTime Then
                                    jRow.Count += 1
                                    jRow.Last = LogTime
                                    'Check how many fail log are from the same ip in the previous CheckMinutes, if there are at least the CheckCount the IP will be banned                                    
                                    If LogTable.Where(Function(x) x.IP = ip And x.DateTime >= Now.AddMinutes(-Cfg.CheckMinutes)).Count >= Cfg.CheckCount And DateDiff(DateInterval.Minute, jRow.First, jRow.Last) < Cfg.CheckMinutes Then
                                        jRow.Banned = MainModule.Jail(ip)
                                        If jRow.Banned Then
                                            BanList.Add(ip)
                                        End If
                                    End If
                                End If
                                'Check if the same ip has reached the overall threshold limit
                                If jRow.Count > Cfg.OverallThreshold And Not jRow.Banned Then
                                    jRow.Banned = MainModule.Jail(ip)
                                End If
                            End If
                        End If
                        LogEntry = LogReader.ReadLine
                    End While
                End If
            End If
            DrawTable(JailTable)

            Dim j = JsonConvert.SerializeObject(JailTable)
            My.Computer.FileSystem.WriteAllText(Cfg.JailFileName, j, False)

            'Need do free memory
            GC.Collect()

            Threading.Thread.Sleep(Cfg.SleepTime)
            LastQueryTime = StartQueryTime
        End While
    End Sub

    Private Sub Discover()
        Console.ForegroundColor = ConsoleColor.White
        Console.WriteLine("Discovery mode is turned on.")
        Console.ResetColor()
        Console.ForegroundColor = ConsoleColor.Red
        Dim errors = False
        If DiscoveryLog = "" Then Console.WriteLine("Log parameter not set, specify the log path.") : errors = True
        If DiscoveryEventId = 0 Then Console.WriteLine("Event ID parameter not set, specify the event id to listen.") : errors = True
        Console.ResetColor()
        Console.WriteLine("Reading " & DiscoveryLog & "...")
        Dim query As EventLogQuery = Nothing
        Try
            query = New EventLogQuery(DiscoveryLog, PathType.LogName) ', "*[System/Level=2]")
        Catch ex As Exception
            Console.ForegroundColor = ConsoleColor.Red
            Console.WriteLine(DiscoveryLog & ": " & ex.Message)
            Console.ResetColor()
        End Try
        If query IsNot Nothing Then
            Using reader = New EventLogReader(query)
                Dim e = reader.ReadEvent()
                While Not e Is Nothing
                    If e.Id = DiscoveryEventId Then
                        Console.WriteLine("Index | Value")
                        For i = 0 To e.Properties.Count - 1
                            Console.WriteLine($"{i,5} | {e.Properties(i).Value}")
                        Next
                        Console.WriteLine("Read next event? (Y/N)")
                        If Console.ReadLine.Trim.ToUpper = "N" Then Exit Sub
                    End If
                    'Need to free memory
                    e.Dispose()
                    e = Nothing

                    e = reader.ReadEvent()
                End While
            End Using
        End If
    End Sub

    Private Function GetResult(value As String, regex As String) As String
        Dim ResultList = New Specialized.StringCollection()
        Try
            Dim RegexObj As New Text.RegularExpressions.Regex(regex)
            Dim MatchResult As Text.RegularExpressions.Match = RegexObj.Match(value)
            While MatchResult.Success
                ResultList.Add(MatchResult.Value)
                MatchResult = MatchResult.NextMatch()
            End While
            RegexObj = Nothing
            MatchResult = Nothing
        Catch ex As ArgumentException
            'Syntax error in the regular expression
        End Try
        If ResultList.Count > 0 Then
            Return ResultList(0)
        Else
            Return ""
        End If
    End Function

    Private Sub DrawTable(JailTable As JailDataSet.JailDataTable)
        Dim html As New IO.StringWriter
        html.Write("<html><body>")
        Console.Clear()
        If JailTable.Count = 0 Then
            Console.WriteLine("Table is empty!")
            html.Write("Table is empty!")
        Else
            'Getting the columns content max width into a list
            Dim GetColumnMaxWidth = Function(ColumnName As String) As Integer
                                        Dim longRow = JailTable.OrderByDescending(Function(x) If(x.IsNull(ColumnName), 0, x.Item(ColumnName).ToString.Length)).First
                                        Return Math.Max(If(longRow.IsNull(ColumnName), 0, longRow.Item(ColumnName).ToString.Length), ColumnName.Length)
                                    End Function

            Dim ColumnsWidth = From c As DataColumn In JailTable.Columns
                               Select New With {
                                  .ColumnName = c.ColumnName,
                                  .Width = GetColumnMaxWidth(c.ColumnName) + 1
                                  }

            'Creating the table header
            Dim HeaderFields As New List(Of String)
            For Each c In ColumnsWidth
                HeaderFields.Add(c.ColumnName.PadRight(c.Width))
            Next
            Dim header = Join(HeaderFields.ToArray, "|")
            Console.WriteLine(header)
            Console.WriteLine("-".PadRight(header.Length, "-"))
            html.Write("<table>")
            html.Write("<tr><th>" & Join(HeaderFields.ToArray, "</th><th>") & "</th></tr>")
            'Adding rows
            Dim rowcount As Integer = 0
            For Each r In JailTable.OrderByDescending(Function(x) If(FullLog, x.Count, x.Last))
                If rowcount < Console.WindowHeight - 8 Then html.Write("<tr>")
                For Each c In ColumnsWidth
                    Dim Data = If(r.IsNull(c.ColumnName), "", r.Item(c.ColumnName)).ToString.PadLeft(c.Width)
                    Select Case c.ColumnName
                        Case "IP"
                            If Cfg.WhiteList.Contains(r.IP) Then Console.ForegroundColor = ConsoleColor.White
                        Case "Count"
                            If r.Count >= Cfg.CheckCount And Not r.Banned Then Console.ForegroundColor = ConsoleColor.Red
                        Case "First", "Last"
                            If DateDiff(DateInterval.Second, r.Item(c.ColumnName), Now) <= Cfg.SleepTime / 1000 Then Console.ForegroundColor = ConsoleColor.Yellow
                        Case "Banned"
                            If r.Banned Then Console.ForegroundColor = ConsoleColor.Green
                    End Select
                    'if output full table or lines added are less than the console height
                    If FullLog Or rowcount < Console.WindowHeight - 8 Then
                        Console.Write(Data)
                        Console.ResetColor()
                        If c.ColumnName <> "Banned" Then
                            Console.Write("|")
                        Else
                            Console.WriteLine("")
                        End If
                        html.Write("<td>" & If(r.IsNull(c.ColumnName), "&nbsp;", r.Item(c.ColumnName)).ToString & "</td>")
                    End If
                Next
                If rowcount < Console.WindowHeight - 8 Then
                    html.Write("</tr>")
                Else
                    Exit For
                End If
                rowcount += 1
            Next

            'Total row
            Console.ResetColor()
            Console.WriteLine("-".PadRight(header.Length, "-"))
            Dim TotalsFields As New List(Of String)
            For Each c In ColumnsWidth
                Dim Data = ""
                Select Case c.ColumnName
                    Case "IP"
                        Data = "Tot: " & JailTable.Count
                    Case "Count"
                        Data = JailTable.Select(Function(x) x.Count).Sum
                    Case "First"
                        Data = $"Worktime: {DateDiff(DateInterval.Hour, StartTime, Now)} h"
                    Case "Last"
                        Data = Now.ToString("HH:mm:ss")
                    Case "Banned"
                        Data = JailTable.Where(Function(x) x.Banned).Count
                End Select
                TotalsFields.Add(Data.PadLeft(c.Width))
            Next
            Console.WriteLine(Join(TotalsFields.ToArray, "|"))
            Console.WriteLine("-".PadRight(header.Length, "-"))
            html.Write("<tr><td><b>" & Join(TotalsFields.ToArray, "</b></td><td>") & "</b></td></tr>")
            html.Write("</table>")
        End If
        html.Write("</body></html>")
        My.Computer.FileSystem.WriteAllText("Jail2ban.html", html.ToString, False)
    End Sub

#Region " Firewall management "

    Dim _fwPolicy As INetFwPolicy2
    Function fwPolicy() As INetFwPolicy2
        If _fwPolicy Is Nothing Then
            _fwPolicy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"))
        End If
        Return _fwPolicy
    End Function

    Function GetRule(IP As String) As INetFwRule2

        Dim RuleName = $"{Cfg.FirewallRuleName} {IP.Split(".")(0) }.{IP.Split(".")(1)}.x.x"

        Dim Rules = From x As INetFwRule2 In fwPolicy.Rules
                    Where x.Name = RuleName

        Dim RuleType = Type.GetTypeFromProgID("HNetCfg.FWRule")
        Dim Rule As INetFwRule2 = Rules.FirstOrDefault
        If Rule Is Nothing Then
            Rule = Activator.CreateInstance(RuleType)
            Rule.Name = RuleName
            Rule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN
            Rule.Protocol = NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_ANY
            Rule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK
            Rule.Enabled = True
            Rule.RemoteAddresses = IP
            fwPolicy.Rules.Add(Rule)
        End If
        Return Rule
    End Function

    Function Jail(IP As String) As Boolean

        'Check into WhiteList
        If Cfg.WhiteList.Contains(IP) Or IP = "-" Or Not IsNumeric(IP.Replace(".", "")) Then
            Return False
        End If

        'Act on the rule
        Dim Rule As INetFwRule2 = GetRule(IP)
        Dim list = Rule.RemoteAddresses.Split(",").ToList
        If Not list.Any(Function(x) x.Split("/")(0) = IP) Then
            list.Add(IP)
            Dim a = list.OrderBy(Function(x) x).ToArray
            'Adding the IP to the ban list
            Rule.RemoteAddresses = Join(a, ",")
        Else
            'IP is already in the ban list
        End If
        Return True

    End Function

#End Region

End Module
