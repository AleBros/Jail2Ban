Imports System.ComponentModel
Imports System.Security.Cryptography

Public Class ConfigurationModel

    Public Property FirewallRuleName = "Jail2Ban block" ' What we name our Rule
    Public Property CheckMinutes = 120  ' We check the most recent X minutes of log.       Default: 120
    Public Property CheckCount = 5      ' Ban after this many failures in search period.   Default: 5
    Public Property SleepTime = 10000
    Public Property JailFileName = "Jail.json"

    ''' <summary>
    ''' List of Safe IPs. Key = IP, Value = Description
    ''' </summary>
    ''' <returns></returns>
    Public Property WhiteList As List(Of WhiteListEntry) = New List(Of WhiteListEntry) From
        {
            New WhiteListEntry With {.IPAddress = "127.0.0.1", .Description = "localhost"}
        }

    'Public Property EventsToCheck As New JailDataSet.EventToCheckDataTable
    Public Property OverallThreshold As Integer = 100
    Public Property LockLocalAddresses As Boolean = False

    Public Property IISWebSitesLogFolder As String = "C:\inetpub\Logs\LogFiles\"
    Public Property SearchFor404inIISLog As Boolean = True
    Public Property Error404BlockList As List(Of String) = New List(Of String) From
        {
            ".php",
            "phpmyadmin",
            "phpadmin",
            "wp-admin",
            "config.json"
        }

    Public Class WhiteListEntry
        Public Property IPAddress As String
        Public Property Description As String
    End Class

End Class

