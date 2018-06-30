Imports NetFwTypeLib
Imports System.Net
Imports System.Linq
Imports System
Imports System.Diagnostics
Imports System.Threading
Imports System.Diagnostics.Eventing.Reader

Module MainModule

    Dim WhiteList As New List(Of String)
    Dim FirewallRuleName = "Jail2Ban block" ' What we name our Rules
    Dim CheckMinutes = 120  ' We check the most recent X minutes of log.       Default: 120
    Dim CheckCount = 5    ' Ban after this many failures in search period.     Default: 5
    Dim SleepTime = 10000
    Dim JailFileName = "Jail.json"

    Sub Main()

        'Populate the WhiteList with machine address
        For Each sl In (From x In Dns.GetHostEntry(Dns.GetHostName).AddressList)
            WhiteList.Add(sl.ToString)
        Next

        'Load History
        Dim fails As New JailDataSet.JailDataTable
        If IO.File.Exists(JailFileName) Then
            fails = Newtonsoft.Json.JsonConvert.DeserializeObject(Of JailDataSet.JailDataTable)(IO.File.ReadAllText(JailFileName))
        End If

        While True

            Dim LogName = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
            Dim query = New EventLogQuery(LogName, PathType.LogName) ', "*[System/Level=2]")

            Using reader = New EventLogReader(query)
                Dim e = reader.ReadEvent()
                While Not e Is Nothing
                    If e.Id = 140 Then
                        Dim ip = e.Properties(0).Value
                        Dim fRow = fails.FindByIP(ip)
                        If fRow Is Nothing Then
                            fRow = fails.AddJailRow(ip, 1, e.TimeCreated, e.TimeCreated, False)
                        End If
                        If fRow.Last < e.TimeCreated Then
                            fRow.Count += 1
                            fRow.Last = e.TimeCreated
                            If fRow.Count >= CheckCount And DateDiff(DateInterval.Minute, fRow.First, fRow.Last) < CheckMinutes Then
                                Jail(ip)
                                fRow.Banned = True
                            End If
                        End If
                    End If
                    e = reader.ReadEvent()
                End While
            End Using
            DrawTable(fails)
            Console.WriteLine("Time " & Now.ToShortTimeString)

            Dim j = Newtonsoft.Json.JsonConvert.SerializeObject(fails)
            My.Computer.FileSystem.WriteAllText(JailFileName, j, False)

            Threading.Thread.Sleep(SleepTime)
        End While

    End Sub

    Private Sub DrawTable(fails As JailDataSet.JailDataTable)
        Console.Clear()
        If fails.Count = 0 Then
            Console.WriteLine("Table is empty!")
        Else
            'Getting the columns content max width into a list
            Dim GetColumnMaxWidth = Function(ColumnName As String) As Integer
                                        Dim longRow = fails.OrderByDescending(Function(x) If(x.IsNull(ColumnName), 0, x.Item(ColumnName).ToString.Length)).First
                                        Return Math.Max(If(longRow.IsNull(ColumnName), 0, longRow.Item(ColumnName).ToString.Length), ColumnName.Length)
                                    End Function

            Dim ColumnsWidth = From c As DataColumn In fails.Columns
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
            For Each r In fails.OrderByDescending(Function(x) x.Count)
                Dim DataFields As New List(Of String)
                For Each c In ColumnsWidth
                    DataFields.Add(If(r.IsNull(c.ColumnName), "", r.Item(c.ColumnName)).ToString.PadLeft(c.Width))
                Next
                Console.WriteLine(Join(DataFields.ToArray, "|"))
            Next

            'Total row
            Console.WriteLine("-".PadRight(header.Length, "-"))
            Dim TotalsFields As New List(Of String)
            For Each c In ColumnsWidth
                Dim Data = ""
                Select Case c.ColumnName
                    Case "IP"
                        Data = "Tot: " & fails.Count
                    Case "Count"
                        Data = fails.Select(Function(x) x.Count).Sum
                    Case "Banned"
                        Data = fails.Where(Function(x) x.Banned).Count
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
                    Where x.Name = FirewallRuleName

        Return Rules.FirstOrDefault
    End Function

    Function Jail(IP As String) As String
        If IP.Contains("/") Then
            IP = IP.Substring(0, IP.IndexOf("/"))
        End If
        If WhiteList.Contains(IP) Then
            Return IP & " whitelisted!"
        End If
        Dim RuleType = Type.GetTypeFromProgID("HNetCfg.FWRule")
        Dim Rule As INetFwRule2 = GetRule()
        If Rule Is Nothing Then
            Rule = Activator.CreateInstance(RuleType)
            Rule.Name = FirewallRuleName
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
                Rule.RemoteAddresses = Join(a, ",")
                Return $"IP {IP} banned!"
            Else
                'Console.WriteLine($"IP {IP} already banned.")
            End If
        End If
        Return ""
    End Function

#End Region


End Module
