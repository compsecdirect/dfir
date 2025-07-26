// main.js
fetch('log_data.json')
  .then(res => res.json())
  .then(data => {
    const suspiciousEvents = [4625, 4672, 4688, 4698, 7045, 1102, 4720, 4724, 4648, 106, 4732, 4728, 4776, 1149, 4663, 4670, 4657, 2004, 2005, 2006, 2007, 5140, 5142, 5143, 5144, 5145, 5168, 3000, 4656, 4658];
    const mitreMap = {
      4625: 'Brute Force (T1110)',
      4648: 'Use of Credentials (T1550)',
      4672: 'Priv. Esc. (T1078)',
      4776: 'Credential Validation (T1110)',
      1149: 'Remote Access (T1021.001)',
      4698: 'Scheduled Task (T1053)',
      106: 'Scheduled Task (T1053)',
      7045: 'Service Execution (T1543.003)',
      4732: 'Permission Group Addition (T1098)',
      4728: 'Permission Group Addition (T1098)',
      4720: 'Account Creation (T1136)',
      4724: 'Account Manipulation (T1098)',
      1102: 'Clear Logs (T1070.001)',
      4663: 'File Access (T1005)',
      4670: 'Permission Modification (T1222)',
      4657: 'Registry Modification (T1112)',
      2004: 'Firewall Rule Added (T1562)',
      2005: 'Firewall Rule Modified (T1562)',
      2006: 'Firewall Rule Deleted (T1562)',
      2007: 'Firewall Settings Changed (T1562)',
      5140: 'SMB Share Access (T1021.002)',
      5142: 'SMB Share Created (T1021.002)',
      5143: 'SMB Share Modified (T1021.002)',
      5144: 'SMB Share Deleted (T1021.002)',
      5145: 'Detailed SMB Access (T1021.002)',
      5168: 'Directory Service Object Modified (T1482)',
      3000: 'SMB Session Info (T1021.002)',
      4656: 'Object Access Attempted (T1005)',
      4658: 'Object Access Closed (T1005)'
    };

    const table = $('#logTable').DataTable({
      data: data,
      columns: [
        { data: 'TimeCreated' },
        { data: 'Id' },
        { data: 'LevelDisplayName' },
        { data: 'ProviderName' },
        { data: 'Message' },
        {
          data: 'Id',
          title: 'MITRE ATT&CK',
          render: function (id) {
            return mitreMap[id] || '';
          }
        }
      ],
      pageLength: 10,
      rowCallback: function (row, data) {
        if (suspiciousEvents.includes(data.Id)) {
          $(row).css('background-color', '#7f1d1d');
          $(row).css('color', 'white');
        }
      }
    });

    // Export filtered to CSV
    const exportButton = $('<button class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded mt-4">Export Filtered to CSV</button>');
    exportButton.on('click', () => {
      const filtered = table.rows({ search: 'applied' }).data().toArray();
      let csv = 'TimeCreated,Id,LevelDisplayName,ProviderName,Message,MITRE\n';
      filtered.forEach(row => {
        const mitre = mitreMap[row.Id] || '';
        csv += `"${row.TimeCreated}","${row.Id}","${row.LevelDisplayName}","${row.ProviderName}","${row.Message.replace(/"/g, '""')}","${mitre}"
`;
      });
      const blob = new Blob([csv], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'filtered_logs.csv';
      a.click();
      URL.revokeObjectURL(url);
    });
    $('#logTable').before(exportButton);

    // Charts
    const eventCounts = {};
    const levelCounts = {};

    data.forEach(entry => {
      eventCounts[entry.Id] = (eventCounts[entry.Id] || 0) + 1;
      levelCounts[entry.LevelDisplayName] = (levelCounts[entry.LevelDisplayName] || 0) + 1;
    });

    new Chart(document.getElementById('eventChart'), {
      type: 'bar',
      data: {
        labels: Object.keys(eventCounts),
        datasets: [{
          label: 'Event ID Frequency',
          data: Object.values(eventCounts),
          backgroundColor: 'rgba(54, 162, 235, 0.6)'
        }]
      },
      options: {
        scales: {
          y: {
            beginAtZero: true
          }
        }
      }
    });

    new Chart(document.getElementById('levelChart'), {
      type: 'pie',
      data: {
        labels: Object.keys(levelCounts),
        datasets: [{
          label: 'Event Levels',
          data: Object.values(levelCounts),
          backgroundColor: [
            'rgba(255, 99, 132, 0.6)',
            'rgba(54, 162, 235, 0.6)',
            'rgba(255, 206, 86, 0.6)',
            'rgba(75, 192, 192, 0.6)'
          ]
        }]
      }
    });
  });