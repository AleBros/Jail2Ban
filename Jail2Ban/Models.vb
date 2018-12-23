Public Class ConfigurationModel

    Public Property FirewallRuleName = "Jail2Ban block" ' What we name our Rule
    Public Property CheckMinutes = 120  ' We check the most recent X minutes of log.       Default: 120
    Public Property CheckCount = 5      ' Ban after this many failures in search period.   Default: 5
    Public Property SleepTime = 10000
    Public Property JailFileName = "Jail.json"
    Public Property WhiteList As New List(Of String)
    Public Property EventsToCheck As New JailDataSet.EventToCheckDataTable
    Public Property SearchForIISLogPhp404 As Boolean = True
    Public Property OverallThreshold As Integer = 100

End Class

