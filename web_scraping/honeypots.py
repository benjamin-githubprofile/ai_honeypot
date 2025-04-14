import json

def get_dummy_financial_data():
    return {
        "January": [
            {"Date": "01/03/2023", "Revenue": "$1,245,678", "Expenses": "$987,654", "Profit": "$258,024", "Department": "Sales"},
            {"Date": "01/07/2023", "Revenue": "$876,543", "Expenses": "$567,890", "Profit": "$308,653", "Department": "Marketing"},
            {"Date": "01/12/2023", "Revenue": "$1,987,654", "Expenses": "$1,234,567", "Profit": "$753,087", "Department": "Operations"},
            {"Date": "01/15/2023", "Revenue": "$2,345,678", "Expenses": "$1,876,543", "Profit": "$469,135", "Department": "Sales"},
            {"Date": "01/18/2023", "Revenue": "$1,456,789", "Expenses": "$987,654", "Profit": "$469,135", "Department": "R&D"},
            {"Date": "01/21/2023", "Revenue": "$2,987,654", "Expenses": "$1,765,432", "Profit": "$1,222,222", "Department": "Sales"},
            {"Date": "01/24/2023", "Revenue": "$1,765,432", "Expenses": "$1,234,567", "Profit": "$530,865", "Department": "Marketing"},
            {"Date": "01/27/2023", "Revenue": "$3,456,789", "Expenses": "$2,345,678", "Profit": "$1,111,111", "Department": "Operations"},
            {"Date": "01/29/2023", "Revenue": "$2,345,678", "Expenses": "$1,456,789", "Profit": "$888,889", "Department": "Sales"},
            {"Date": "01/31/2023", "Revenue": "$4,567,890", "Expenses": "$3,456,789", "Profit": "$1,111,101", "Department": "Executive"}
        ],
        "February": [
            {"Date": "02/02/2023", "Revenue": "$2,345,678", "Expenses": "$1,987,654", "Profit": "$358,024", "Department": "Sales"},
            {"Date": "02/05/2023", "Revenue": "$1,876,543", "Expenses": "$1,234,567", "Profit": "$641,976", "Department": "Marketing"},
            {"Date": "02/08/2023", "Revenue": "$3,456,789", "Expenses": "$2,345,678", "Profit": "$1,111,111", "Department": "Operations"},
            {"Date": "02/11/2023", "Revenue": "$2,987,654", "Expenses": "$2,345,678", "Profit": "$641,976", "Department": "Sales"},
            {"Date": "02/14/2023", "Revenue": "$1,876,543", "Expenses": "$1,234,567", "Profit": "$641,976", "Department": "R&D"},
            {"Date": "02/17/2023", "Revenue": "$3,456,789", "Expenses": "$2,345,678", "Profit": "$1,111,111", "Department": "Sales"},
            {"Date": "02/20/2023", "Revenue": "$2,345,678", "Expenses": "$1,456,789", "Profit": "$888,889", "Department": "Marketing"},
            {"Date": "02/23/2023", "Revenue": "$4,567,890", "Expenses": "$3,456,789", "Profit": "$1,111,101", "Department": "Operations"},
            {"Date": "02/26/2023", "Revenue": "$3,987,654", "Expenses": "$2,876,543", "Profit": "$1,111,111", "Department": "Sales"},
            {"Date": "02/28/2023", "Revenue": "$5,678,901", "Expenses": "$4,567,890", "Profit": "$1,111,011", "Department": "Executive"}
        ]
    }

def get_dummy_customer_data():
    return [
        {"ID": "C001", "Name": "Acme Corporation", "Email": "contact@acme.com", "Phone": "555-123-4567", "Value": "$1,245,678"},
        {"ID": "C002", "Name": "Globex Industries", "Email": "info@globex.com", "Phone": "555-234-5678", "Value": "$987,654"},
        {"ID": "C003", "Name": "Umbrella Corp", "Email": "sales@umbrella.com", "Phone": "555-345-6789", "Value": "$2,345,678"},
        {"ID": "C004", "Name": "Stark Industries", "Email": "tony@stark.com", "Phone": "555-456-7890", "Value": "$5,432,109"},
        {"ID": "C005", "Name": "Wayne Enterprises", "Email": "bruce@wayne.com", "Phone": "555-567-8901", "Value": "$4,321,098"},
        {"ID": "C006", "Name": "Oscorp", "Email": "contact@oscorp.com", "Phone": "555-678-9012", "Value": "$1,234,567"},
        {"ID": "C007", "Name": "Cyberdyne Systems", "Email": "info@cyberdyne.com", "Phone": "555-789-0123", "Value": "$3,456,789"},
        {"ID": "C008", "Name": "LexCorp", "Email": "lex@lexcorp.com", "Phone": "555-890-1234", "Value": "$2,345,678"},
        {"ID": "C009", "Name": "Initech", "Email": "tps@initech.com", "Phone": "555-901-2345", "Value": "$876,543"},
        {"ID": "C010", "Name": "Weyland-Yutani", "Email": "contact@weyland.com", "Phone": "555-012-3456", "Value": "$4,567,890"}
    ]

def get_dummy_api_keys():
    return [
        {"Service": "AWS", "Key": "AKIA1234567890ABCDEF", "Created": "2023-01-15", "Expires": "2024-01-15", "Owner": "DevOps"},
        {"Service": "Google Cloud", "Key": "AIzaSyA1a2b3c4d5e6f7g8h9i0jklmnopqrstu", "Created": "2023-02-20", "Expires": "2024-02-20", "Owner": "Data Science"},
        {"Service": "Azure", "Key": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6", "Created": "2023-03-10", "Expires": "2024-03-10", "Owner": "Web Team"},
        {"Service": "GitHub", "Key": "ghp_abcdefghijklmnopqrstuvwxyz123456", "Created": "2023-04-05", "Expires": "2024-04-05", "Owner": "Engineering"},
        {"Service": "Stripe", "Key": "sk_test_1234567890abcdefghijklmnopqrstuvwxyz", "Created": "2023-05-15", "Expires": "2024-05-15", "Owner": "Finance"},
        {"Service": "Salesforce", "Key": "00D1a2b3c4d5e6f7g8h9i0_EXAMPLE12345", "Created": "2023-06-20", "Expires": "2024-06-20", "Owner": "Sales"},
        {"Service": "Twilio", "Key": "ACa1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6", "Created": "2023-07-10", "Expires": "2024-07-10", "Owner": "Marketing"},
        {"Service": "SendGrid", "Key": "SG.1234567890abcdefghijklmnopqrstuvwxyz", "Created": "2023-08-15", "Expires": "2024-08-15", "Owner": "Communications"},
        {"Service": "Mailchimp", "Key": "a1b2c3d4e5f6g7h8i9j0-us21", "Created": "2023-09-20", "Expires": "2024-09-20", "Owner": "Content Team"},
        {"Service": "Internal API", "Key": "int_1a2b3c4d5e6f7g8h9i0j_secret", "Created": "2023-10-10", "Expires": "2024-10-10", "Owner": "Product"}
    ]