### Exporting a sheet as CSV via Google Chart Tools API

https://medium.com/@scottcents/how-to-convert-google-sheets-to-json-in-just-3-steps-228fe2c24e6

1. Share > All can view with link

2. Grab SpreadsheetID from browser URL:
https://docs.google.com/spreadsheets/d/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/edit#gid=yyyyyyyyyy
-->
Spreadsheet ID:
1qswMijuMmv6wzbPzx8B8IBX3e1-otjM1Hk06KzxhQOE

3. Test Chart Tools datasource protocol

Http API: https://docs.google.com/spreadsheets/d/{key}/gviz/tq?tqx=out:csv&sheet={sheet_name}
-->
https://docs.google.com/spreadsheets/d/1qswMijuMmv6wzbPzx8B8IBX3e1-otjM1Hk06KzxhQOE/gviz/tq?tqx=out:csv&sheet=Ilmiöt


### Notes:

- If cURL is used to fetch the CSV, include url in 'quotes', otherwise something goes silently wrong...
- Use English locale to ensure numbers have a dot (.) separator instad of comma (,)
- Header line may need a "EOF" column with a dummy value 1 below it to prevent header garbling
