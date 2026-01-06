# QR Guard API Documentation

<<<<<<< HEAD





QR Guard is a URL security analysis API.  


It analyzes URLs using:


- **VirusTotal** (external intelligence)


- **Custom risk analysis engine**


- *(Optional)* AI-generated report (future)





---





## Base URL





```


http://localhost:3000


```





> Change this to production URL when deployed.





---





## Authentication





Most endpoints require **JWT authentication**.





### How authentication works


1. User logs in


2. Backend returns a JWT token


3. Frontend sends token in `Authorization` header





```http


Authorization: Bearer <token>


```





---





## Login





### Endpoint


```


POST /auth/login


```





### Request Body


```json


{


  "email": "user@example.com",


  "password": "password123"


}


```





### Response


```json


{


  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."


}


```





---





## Check URL (Main Feature)





### Endpoint


```


POST /check


```





### Headers


```http


Authorization: Bearer <token>


Content-Type: application/json


```





### Request Body


```json


{


  "url": "https://example.com"


}


```





---





## Response Structure





The response contains **three analysis layers**:





1. **VirusTotal Results** - Raw results from VirusTotal


2. **My API Results** - Custom risk score + verdict


3. **(Optional) AI Report** - Human-readable explanation *(future)*





### Example Response


```json


{


  "url": "https://example.com",





  "virustotal": {


    "analysisId": "YTQxN2M4Z...",


    "stats": {


      "harmless": 84,


      "malicious": 2,


      "suspicious": 1,


      "undetected": 13


    },


    "full_report": {


      "...": "Full VirusTotal response"


    }


  },





  "my_api": {


    "risk_score": 28,


    "verdict": "suspicious",


    "color": "yellow",


    "flags": [


      "Redirect chain detected",


      "Phishing keyword detected"


    ]


  }


}


```





---





## Risk Score Meaning





| Score Range | Verdict | Meaning |


|------------|--------|--------|


| 0 | clean | No risk detected |


| 1–20 | safe | Low risk |


| 21–50 | suspicious | Medium risk |


| 51–100 | malicious | High risk |





---





## Verdict Colors (UI)





| Verdict | Color |


|-------|-------|


| clean | green |


| safe | lightgreen |


| suspicious | yellow |


| malicious | red |





---





## Error Responses





### Missing URL


```json


{


  "error": "URL is required"


}


```





### Unauthorized


```json


{


  "error": "Invalid or missing token"


}


```





### Scan Failure


```json


{


  "error": "URL scan failed",


  "details": "VirusTotal API error"


}


```





---





## Test URLs (Use Carefully)





⚠️ **For testing only**





```


http://testsafebrowsing.appspot.com/s/malware.html


http://malware.wicar.org/data/eicar.com


```





---





## Frontend Flow (Recommended)





1. User scans QR code (camera)


2. Extract URL


3. Send URL to `/check`


4. Display:


   - Verdict


   - Risk score


   - Color


   - Flags


5. Optionally download PDF report (future)





---





## Future Features





- PDF report generation


- AI explanation


- Scan history


- Bulk URL scanning





---





## Tech Notes (for frontend dev)





- API returns **JSON only**


- Always expect async responses


- Handle loading state (VirusTotal may take seconds)


- Token must be stored securely





---





## Summary





- `/auth/login` → get token


- `/check` → analyze URL


- Use `verdict + color` for UI


=======
QR Guard is a URL security analysis API.  
It analyzes URLs using:
- **VirusTotal** (external intelligence)
- **Custom risk analysis engine**
- *(Optional)* AI-generated report (future)

---

## Base URL

```
http://localhost:3000
```

> Change this to production URL when deployed.

---

## Authentication

Most endpoints require **JWT authentication**.

### How authentication works
1. User logs in
2. Backend returns a JWT token
3. Frontend sends token in `Authorization` header

```http
Authorization: Bearer <token>
```

---

## Login

### Endpoint
```
POST /auth/login
```

### Request Body
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

### Response
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

## Check URL (Main Feature)

### Endpoint
```
POST /check
```

### Headers
```http
Authorization: Bearer <token>
Content-Type: application/json
```

### Request Body
```json
{
  "url": "https://example.com"
}
```

---

## Response Structure

The response contains **three analysis layers**:

1. **VirusTotal Results** - Raw results from VirusTotal
2. **My API Results** - Custom risk score + verdict
3. **(Optional) AI Report** - Human-readable explanation *(future)*

### Example Response
```json
{
  "url": "https://example.com",

  "virustotal": {
    "analysisId": "YTQxN2M4Z...",
    "stats": {
      "harmless": 84,
      "malicious": 2,
      "suspicious": 1,
      "undetected": 13
    },
    "full_report": {
      "...": "Full VirusTotal response"
    }
  },

  "my_api": {
    "risk_score": 28,
    "verdict": "suspicious",
    "color": "yellow",
    "flags": [
      "Redirect chain detected",
      "Phishing keyword detected"
    ]
  }
}
```

---

## Risk Score Meaning

| Score Range | Verdict | Meaning |
|------------|--------|--------|
| 0 | clean | No risk detected |
| 1–20 | safe | Low risk |
| 21–50 | suspicious | Medium risk |
| 51–100 | malicious | High risk |

---

## Verdict Colors (UI)

| Verdict | Color |
|-------|-------|
| clean | green |
| safe | lightgreen |
| suspicious | yellow |
| malicious | red |

---

## Error Responses

### Missing URL
```json
{
  "error": "URL is required"
}
```

### Unauthorized
```json
{
  "error": "Invalid or missing token"
}
```

### Scan Failure
```json
{
  "error": "URL scan failed",
  "details": "VirusTotal API error"
}
```

---

## Test URLs (Use Carefully)

⚠️ **For testing only**

```
http://testsafebrowsing.appspot.com/s/malware.html
http://malware.wicar.org/data/eicar.com
```

---

## Frontend Flow (Recommended)

1. User scans QR code (camera)
2. Extract URL
3. Send URL to `/check`
4. Display:
   - Verdict
   - Risk score
   - Color
   - Flags
5. Optionally download PDF report (future)

---

## Future Features

- PDF report generation
- AI explanation
- Scan history
- Bulk URL scanning

---

## Tech Notes (for frontend dev)

- API returns **JSON only**
- Always expect async responses
- Handle loading state (VirusTotal may take seconds)
- Token must be stored securely

---

## Summary

- `/auth/login` → get token
- `/check` → analyze URL
- Use `verdict + color` for UI
>>>>>>> 6f8deb69a303597825fdc72ccbac0b0a9a7decc1
- Use `virustotal.stats` for detailed view

