### Exporting a sheet as CSV via Google Chart Tools API

https://medium.com/@scottcents/how-to-convert-google-sheets-to-json-in-just-3-steps-228fe2c24e6

1. Share > All can view with link

2. Grab SpreadsheetID from browser URL:
https://docs.google.com/spreadsheets/d/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/edit#gid=yyyyyyyyyy
-->
Spreadsheet ID:
1TC64MdbWpGMFlxRB4SClSxYMzOw6es5TTxr-18qKXUs

3. Test Chart Tools datasource protocol

Http API: https://docs.google.com/spreadsheets/d/{key}/gviz/tq?tqx=out:csv&sheet={sheet_name}

### Notes:

- If cURL is used to fetch the CSV, include url in 'quotes', otherwise something goes silently wrong...
- Use English locale to ensure numbers have a dot (.) separator instad of comma (,)
- Header line may need a "EOF" column with a dummy value 1 below it to prevent header garbling
