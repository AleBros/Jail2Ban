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
            End Select
        Next

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
        For Each sl In (From x In Dns.GetHostEntry(Dns.GetHostName).AddressList)
            Cfg.WhiteList.Add(sl.ToString)
            Console.WriteLine($" - {sl.ToString}")
        Next
        Console.WriteLine("")

        'Load History
        Console.WriteLine("Loading history file...")
        Dim JailTable As New JailDataSet.JailDataTable
        If IO.File.Exists(Cfg.JailFileName) Then
            JailTable = JsonConvert.DeserializeObject(Of JailDataSet.JailDataTable)(IO.File.ReadAllText(Cfg.JailFileName))
        End If

        'Lock IPs basing on the history file (in case you need to recreate the block rule loading another computer history)
        For Each row In JailTable.Where(Function(x) x.Banned Or (x.Count >= Cfg.CheckCount And DateDiff(DateInterval.Minute, x.First, x.Last) < Cfg.CheckMinutes))
            row.Banned = MainModule.Jail(row.IP)
        Next
        Console.WriteLine("")

        Console.WriteLine("Application starts in 5 seconds.")
        Threading.Thread.Sleep(5000)

        Dim EventsToCheck = New JailDataSet.EventToCheckDataTable
        EventsToCheck.AddEventToCheckRow("Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", 140, 0)
        EventsToCheck.AddEventToCheckRow("Security", 4625, 19)

        'Starts the infinite loop
        While True

            For Each etcRow In EventsToCheck
                Console.WriteLine("Reading " & etcRow.Log & "...")
                Dim query As EventLogQuery
                Try
                    query = New EventLogQuery(etcRow.Log, PathType.LogName) ', "*[System/Level=2]")
                Catch ex As Exception
                    Console.ForegroundColor = ConsoleColor.Red
                    Console.WriteLine(etcRow.Log & ": " & ex.Message)
                    Console.ResetColor()
                    GoTo NextEventType
                End Try

                Using reader = New EventLogReader(query)
                    Dim e = reader.ReadEvent()
                    While Not e Is Nothing
                        If e.Id = etcRow.EventID Then
                            Dim ip = e.Properties(etcRow.PropertyIndex).Value
                            Dim row = JailTable.FindByIP(ip)
                            If row Is Nothing Then
                                row = JailTable.AddJailRow(ip, 1, e.TimeCreated, e.TimeCreated, False)
                            End If
                            If row.Last < e.TimeCreated Then
                                row.Count += 1
                                row.Last = e.TimeCreated
                                If row.Count >= Cfg.CheckCount And DateDiff(DateInterval.Minute, row.First, row.Last) < Cfg.CheckMinutes Then
                                    row.Banned = MainModule.Jail(ip)
                                End If
                            End If
                        End If
                        e = reader.ReadEvent()
                    End While
                End Using
NextEventType:
            Next

            DrawTable(JailTable)

            Dim j = JsonConvert.SerializeObject(JailTable)
            My.Computer.FileSystem.WriteAllText(Cfg.JailFileName, j, False)

            Threading.Thread.Sleep(Cfg.SleepTime)
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
                    Console.WriteLine("Index | Value")
                    If e.Id = DiscoveryEventId Then
                        For i = 0 To e.Properties.Count - 1
                            Console.WriteLine($"{i,5} | {e.Properties(i).Value}")
                        Next
                    End If
                    Console.WriteLine("Read next event? (Y/N)")
                    If Console.ReadLine.Trim.ToUpper = "N" Then Exit Sub

                    e = reader.ReadEvent()
                End While
            End Using
        End If
    End Sub

    Private Sub DrawTable(JailTable As JailDataSet.JailDataTable)
        Console.Clear()
        If JailTable.Count = 0 Then
            Console.WriteLine("Table is empty!")
        Else
            'Getting the columns content max width into a list
            Dim GetColumnMaxWidth = Function(ColumnName As String) As Integer
                                        Dim longRow = JailTable.OrderByDescending(Function(x) If(x.IsNull(ColumnName), 0, x.Item(ColumnName).ToString.Length)).First
                                        Return Math.Max(If(longRow.IsNull(ColumnName), 0, longRow.Item(ColumnName).ToString.Length), ColumnName.Length)
                                    End Function

            Dim ColumnsWidth = From c As DataColumn In JailTable.Columns
                               Select New With {
                                  .ColumnName = c.ColumnName,
                                  .Width = GetColumnMaxWidth(c.ColumnName)
                                  }

            'Creating the table header
            Dim HeaderFields As New List(Of String)
            For Each c In ColumnsWidth
                HeaderFields.Add(c.ColumnName.PadRight(c.Width))
            Next
            Dim header = Join(HeaderFields.ToArray, "|")
            Console.WriteLine(header)
            Console.WriteLine("-".PadRight(header.Length, "-"))

            'Adding rows
            For Each r In JailTable.OrderByDescending(Function(x) x.Count)
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
                    Console.Write(Data)
                    Console.ResetColor()
                    If c.ColumnName <> "Banned" Then
                        Console.Write("|")
                    Else
                        Console.WriteLine("")
                    End If
                Next
            Next

            'Total row
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
        End If
    End Sub

#Region " Firewall management "

    Dim _fwPolicy As INetFwPolicy2
    Function fwPolicy() As INetFwPolicy2
        If _fwPolicy Is Nothing Then
            _fwPolicy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"))
        End If
        Return _fwPolicy
    End Function

    Function GetRule() As INetFwRule2
        Dim Rules = From x As INetFwRule2 In fwPolicy.Rules
                    Where x.Name = Cfg.FirewallRuleName

        Return Rules.FirstOrDefault
    End Function

    Function Jail(IP As String) As Boolean

        'Check into WhiteList
        If Cfg.WhiteList.Contains(IP) Then
            Return False
        End If

        'Act on the rule
        Dim RuleType = Type.GetTypeFromProgID("HNetCfg.FWRule")
        Dim Rule As INetFwRule2 = GetRule()
        If Rule Is Nothing Then
            Rule = Activator.CreateInstance(RuleType)
            Rule.Name = Cfg.FirewallRuleName
            Rule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN
            Rule.Protocol = NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_ANY
            Rule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK
            Rule.Enabled = True
            Rule.RemoteAddresses = IP
            fwPolicy.Rules.Add(Rule)
        Else
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
        End If
        Return False
    End Function

#End Region

End Module
