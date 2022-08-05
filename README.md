# Automatically Blocking Inactive Users In Auth0

Sample implementation of an offline process that uses the Auth0 management api to identify and then block users who haven't logged in in a certain number of days. **This is a proof of concept and should not be considered production ready code.**

# Prerequisites

- Written in C# this POC requires you have the [.Net Core Runtime or SDK](https://docs.microsoft.com/en-us/dotnet/core/install/dependencies?tabs=netcore30&pivots=os-macos) installed.

- You must define a M2M application in Auth0 to represent this process. The process will use this application's client_id and client_secret to fetch access tokens to call the Auth0 Management Api. The application must be authorized for the Management Api with the read:users and update:users scopes.

# Configuration

The appsettings.json file must be populated with the appropriate values before running.

| Key            | Value                                                                                                                                |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| ClientId       | The client id of the M2M application created in Auth0 to represent this process.                                                     |
| ClientSecret   | The client secret of the same application. **In production use this secret MUST be stored securely not in plaintext as in this POC** |
| A0Domain       | The domain for your Auth0 tenant. ex: `tenantname.auth0.com`.                                                                        |
| BlockThreshold | The required number of days of no logins before users should be blocked.                                                             |
| UserPageSize   | The number of users retrieved by each call to the search user endpoint. Max Value: 100.                                              |

# Running the POC

This POC can be run from the terminal with the `dotnet run` command. To aid testing running `dotnet run -u` will unblock one page of users. The number of uses unblocked will be the value of the UserPageSize setting.
