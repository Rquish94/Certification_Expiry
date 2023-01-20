import re
from email.mime.text import MIMEText
import smtplib
import datetime
from tenable.sc import TenableSC
import logging



logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  datefmt='%d-%b-%y %H:%M:%S')

#Log in security center
securityCenter = TenableSC()
print("Logging into Security Center")
securityCenter.login('', '')
logging.info('Signed into Tenable')

#create a dictionary for month conversion
monthConversion = {'Jan': '1', 'Feb': '2', 'Mar': '3', 'Apr': '4', 'May': '5', 'Jun': '6', 'Jul': '7', 'Aug': '8',
                   'Sep': '9', 'Oct': '10', 'Nov': '11', 'Dec': '12'}
#create empty lists for data
ninety = []
sixty = []
thirty = []
zero = []
internalNinety = []
internalSixty = []
internalThirty = []
internalZero = []
listOcommonnames = []

#loop over certification fields
print("Beginning loop through all results found in pluginID to collect and categorize data")



for vuln in securityCenter.analysis.vulns(('pluginID', '=', '#'), sort_field='name'):
    name = []
    #parse out fields that are in the pluginText
    print('Parsing and categorizing data for  '+str(vuln['ip'])+' - '+str(vuln['port']))
    logging.info('Parsing and categorizing data for  '+str(vuln['ip'])+' - '+str(vuln['port']))

    try:
        for line in str(vuln['pluginText']).replace('\n',r'\n)').split(r'\n'):
            if 'Common Name' in line:
                name.append((str(line).replace('Common Name: ','').replace(')','').replace('(','')))
    except:
        print('Error pulling/parsing common name')
        logging.error('Error pulling/parsing common name line 43')
    #commonName = re.findall('Common Name: (.+?)\\\\n\\\\nSerial Number:',str(vuln['pluginText']), re.DOTALL)
        #print(commonName[0])
    notValidAfter = re.findall('Not Valid After:(.+?)GMT', vuln['pluginText'], re.DOTALL)
    #print(notValidAfter)
    commonName = str(name)
    listOcommonnames.append(str(name))
    if 'go daddy' in commonName.lower() or 'digicert' in commonName.lower() or 'symantec' in commonName.lower() or 'thawte' in commonName.lower():
    #     print(commonName)
    #     print(notValidAfter)
    #narrow data field for cqommonNames we dont want
        #If you find a godaddy,digicert,thawte or symantec cert split into a list so i can take fields out
        print('Catagorized as non ICA')
        try:
            splitNotValidAfter = str(notValidAfter).replace("[' ", '').replace(" ']", '').replace("u'",'').replace(":",'').split(' ')
                    #calculate variable for time
            timeLeft = datetime.date(int(splitNotValidAfter[3]), int((monthConversion[splitNotValidAfter[0]])), int(splitNotValidAfter[1])) - datetime.date.today()
        except:
            print('Error calculating and parsing time')
            logging.error('Error calculating and parsing time line 91.')

        print('-' * 60)
        # print((timeLeft[0]))
                #If it falls within a certain amount of time left categorize it by appending by group
        try:
            if int(timeLeft.days) <= 90 and int(timeLeft.days) > 60:
                ninety.append((timeLeft.days, str(notValidAfter), str(vuln['ip']), commonName.replace(',',' -- '), str(vuln['port']).replace("u",'')))
            elif int(timeLeft.days) <= 60 and int(timeLeft.days) > 30:
                sixty.append((timeLeft.days, str(notValidAfter), str(vuln['ip']), commonName.replace(',',' -- '), str(vuln['port']).replace("u",'')))
            elif int(timeLeft.days) <= 30 and int(timeLeft.days) >= 1:
                thirty.append((int(timeLeft.days), str(notValidAfter)[3:-3], str(vuln['ip']), commonName.replace(',',' -- '), str(vuln['port']).replace("u",'')))
            elif int(timeLeft.days) <= 0 and int(timeLeft.days) >= -30:
                zero.append((int(timeLeft.days), str(notValidAfter)[3:-3], str(vuln['ip']), commonName.replace(',',' -- '), str(vuln['port']).replace("u",'')))
            else:
                continue
        except:
            print('Error finding day grouping and appending to list')
            logging.error('Error finding day grouping and appending to list line 99.')


    #Capturing all others (ICA)
    else:

        print("Categorized as ICA")
        try:
            splitNotValidAfter = str(notValidAfter).replace("[' ", '').replace(" ']", '').split(' ')

            # calculate variable for time
            timeLeft = datetime.date(int(splitNotValidAfter[3]), int((monthConversion[splitNotValidAfter[0]])), int(splitNotValidAfter[1])) - datetime.date.today()
        except:
            print('Error calculating and parsing time')
            logging.error('Error calculating and parsing time line 91.')
        print('-' * 60)
        # If it falls within a certain amount of time left categorize it by appending by group

        try:
            if int(timeLeft.days) <= 90 and int(timeLeft.days) > 60:
                internalNinety.append((timeLeft.days, str(notValidAfter), str(vuln['ip']), commonName.replace(',', ' -- '), str(vuln['port']).replace("u",'')))
            elif int(timeLeft.days) <= 60 and int(timeLeft.days) > 30:
                internalSixty.append((timeLeft.days, str(notValidAfter), str(vuln['ip']), commonName.replace(',', ' -- '), str(vuln['port']).replace("u",'')))
            elif int(timeLeft.days) <= 30 and int(timeLeft.days) >= 1:
                internalThirty.append((int(timeLeft.days), str(notValidAfter)[3:-3], str(vuln['ip']), commonName.replace(',', ' -- '),str(vuln['port']).replace("u",'')))
            elif int(timeLeft.days) <= 0 and int(timeLeft.days) >= -30:
                internalZero.append((int(timeLeft.days), str(notValidAfter)[3:-3], str(vuln['ip']), commonName.replace(',', ' -- '),str(vuln['port']).replace("u",'')))
            else:
                continue
        except:
                print('Error finding day grouping and appending to list')
                logging.error('Error finding day grouping and appending to list line 99.')


#Take in the four different lists of data
def mailFunc2(zero, thirty, sixty, ninety, title):
    logging.info('Beginning Mailing process')
    print('Mailing function beginning')
    htmlZero = []
    htmlThirty = []
    htmlSixty = []
    htmlNinety = []

    if title.lower() == 'e':
        titleHTML = 'NON ICA'
        print('Determined to be '+titleHTML)
    elif title.lower() == 'i':
        titleHTML = 'ICA'
        print('Determined to be '+titleHTML)
    else:
        print('Must enter e for external or i for internal')
        quit()

#Loop through each list and prepare them for HTML entry
    print('preparing HTML')
    try:
        for i in sorted(zero):
            htmlZero.append('<tr><td>' + str(i[0]) + '</td><td>' + i[1] + '</td><td>' + i[2] + '</td><td>' + i[3] + '</td><td>' + i[4] + '</td></tr>')
        for i in sorted(thirty):
            htmlThirty.append('<tr><td>' + str(i[0]) + '</td><td>' + i[1] + '</td><td>' + i[2] + '</td><td>' + i[3] + '</td><td>' + i[4] + '</td></tr>')
        for i in sorted(sixty):
            htmlSixty.append('<tr><td>' + str(i[0]) + '</td><td>' + i[1] + '</td><td>' + i[2] + '</td><td>' + i[3] + '</td><td>' + i[4] + '</td></tr>')
        for i in sorted(ninety):
            htmlNinety.append('<tr><td>' + str(i[0]) + '</td><td>' + i[1] + '</td><td>' + i[2] + '</td><td>' + i[3] + '</td><td>' + i[4] + '</td></tr>')
    except:
        print('Error indexing and appending data')
        logging.error('Error indexing and appending data to HTML lists line 136')
#Decide whos sending and receiving
    sender = '#'
    receiver = '#'

#create the html which will be sent in the email
    msg = MIMEText("""
     <html>
<head>
<style>
table {
  font-family: arial, sans-serif;
  border-collapse: collapse;
  width: 100%;
}
td, th {
  border: 1px solid #dddddd;
  text-align: left;
  padding: 8px;
}
tr:nth-child(even) {
  background-color: #dddddd;
}
</style>
</head>
<body>
<div>
<center><h2>EXPIRED</h2></center>
<table>
  <tr>
    <th style="background-color:#000000;">Days Til Expiration</th>
    <th style="background-color:#000000;">Expires On</th>
    <th style="background-color:#000000;">IP</th>
      <th style="background-color:#000000;">Common Name</th>
      <th style="background-color:#000000;">Port</th>
  </tr>
  """ + str(htmlZero).replace('"', '').replace("'", "").replace('[', '').replace(']', '').replace(',', '').replace('><','>\n<') + """
</table>
</div>
<div>
<center><h2>1-30 DAYS</h2></center>
<table>
  <tr>
    <th style="background-color:#ff4d4d;">Days Til Expiration</th>
    <th style="background-color:#ff4d4d;">Expires On</th>
    <th style="background-color:#ff4d4d;">IP</th>
      <th style="background-color:#ff4d4d;">Common Name</th>
      <th style="background-color:#ff4d4d;">Port</th>
  </tr>
  """ + str(htmlThirty).replace('"', '').replace("'", "").replace('[', '').replace(']', '').replace(',', '').replace('><', '>\n<') + """
</table>
</div>
<div>
<center><h2>31-60 DAYS</h2></center>
<table>
  <tr>
    <th style="background-color:#ffff99;">Days Til Expiration</th>
    <th style="background-color:#ffff99;">Expires On</th>
    <th style="background-color:#ffff99;">IP</th>
      <th style="background-color:#ffff99;">Common Name</th>
      <th style="background-color:#ffff99;">Port</th>
  </tr>
""" + str(htmlSixty).replace('"', '').replace("'", "").replace('[', '').replace(']', '').replace(',', '').replace('><','>\n<') + """
</table>
</div>
<div>
<center><h2>61-90 DAYS</h2></center>
<table>
  <tr>
    <th style="background-color:#adebad;">Days Til Expiration</th>
    <th style="background-color:#adebad;">Expires On</th>
    <th style="background-color:#adebad;">IP</th>
      <th style="background-color:#adebad;">Common Name</th>
      <th style="background-color:#adebad;">Port</th>
  </tr>
  """ + str(htmlNinety).replace('"', '').replace("'", "").replace('[', '').replace(']', '').replace(',', '').replace('><', '>\n<') + """

</table>
</div>
</body>
</html>

     """, 'html')


    msg['Subject'] = 'SAMPLE: SSL CERTIFICATION UPDATE NOTICE -- '+ str(titleHTML)
    msg['From'] = sender
    msg['To'] = receiver

    try:
        smtpObj = smtplib.SMTP('#')
        smtpObj.sendmail(sender, receiver, str(msg))
        smtpObj.quit()
        print('Sending email\n')
        logging.info('Script ran successfully, emails sent.')
    except smtplib.SMTPException:
        print('Error sending email')

mailFunc2(zero, thirty, sixty, ninety,'e')
mailFunc2(internalZero,internalThirty,internalSixty,internalNinety,'i')
#test
