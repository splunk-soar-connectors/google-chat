## Asset Configuration

Before you start any app exploration user have to create App authuentication on GCP to authenticate for API calls. More info under [Google Authenticate](https://developers.google.com/workspace/chat/authenticate-authorize). after user have created the application and have the Client ID, Client Secret and Redirect URI, user can generate authenticate code. To do this open

```bash
https://accounts.google.com/o/oauth2/auth?client_id=<Client_ID>&redirect_uri=<redirect_uri>&response_type=code&scope=https://www.googleapis.com/auth/chat.messages&access_type=offline
```

and pass all veryfication, at the end in new url user will see code variable, examplary

```bash
4/0AeaYSHBzshfJQe5ccwX25jAGkzR5TFNkEyDTL8NrSnqQj4VboVd2TlLx50h6_a7OiG8ZHA
```

Thanks to this we can start asset configuration with all required fields.
