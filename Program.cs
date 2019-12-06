using System;
using System.Threading.Tasks;
using Auth0.ManagementApi;
using Auth0.ManagementApi.Models;
using Auth0.Core.Collections;
using Auth0.Core.Exceptions;
using Auth0.Core.Http;
using RestSharp;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.FileExtensions;
using Microsoft.Extensions.Configuration.Json;
using System.IO;
using System.Collections.Generic;
using System.Net;


namespace AutomatedBlockUsers
{
    class Program
    {

        static IConfigurationRoot configuration;
        static ManagementApiClient MgmtClient;

        static async Task Main(string[] args)
        {
            //setup pulling config from appsettings.json
            var builder = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true);
            configuration = builder.Build();

            //get token to call mgmt api
            var token = (await GetMgmtApiToken()).access_token;

            MgmtClient = new ManagementApiClient(token, GetConfigValue("A0Domain"));

            //for test purposes: run utilty with param of "true" to unblock 1 page of users after testing
            #region unblock users
            if (args.Length > 0 && args[0] == "-u")
            {
                int count = 0;
                var allUsers = await SearchUsers(string.Empty, false, ",blocked");
                foreach (var user in allUsers)
                {
                    if (user.Blocked == true)
                    {
                        count++;
                        await BlockUser(user, false);
                    }
                }

                Console.WriteLine($"Unblocked {count} users.");
                return;
            }
            #endregion

            var BlockThreshold = GetConfigValue("BlockThreshold");
            Console.WriteLine($"Blocking users whose last login was {BlockThreshold} days ago.  Last login occurred on or before: {DateTimeOffset.UtcNow.AddDays(double.Parse(BlockThreshold) * -1).ToString("yyyy-MM-dd")})");

            //block users who have a login date
            int usersBlockedByLogin = await BlockUsers(false);
            Console.WriteLine($"Blocked {usersBlockedByLogin} users based on last_login.");
            Console.WriteLine();

            //block users who have never logged in based on create date.
            int usersBlockedByCreate = await BlockUsers(true);
            Console.WriteLine($"Blocked {usersBlockedByLogin} users based on last_login.");
            Console.WriteLine($"Blocked {usersBlockedByCreate} users based on created_at.");
            Console.WriteLine($"Blocked {usersBlockedByLogin + usersBlockedByCreate} users in total");
        }


        /// <summary>
        /// Identifies and blocks all users based either on last_login or create date if user has never logged in
        /// as indicated by bool param
        /// </summary>
        static async Task<int> BlockUsers(bool forUsersWithNoLogin)
        {
            //build search query to fetch first (up to) 1000 applicable users
            var searchQuery = BuildUserSearchQuery(forUsersWithNoLogin);

            //fetch users that match initial query
            var users = await SearchUsers(searchQuery, forUsersWithNoLogin);

            int blockedUsers = 0;
            User lastUser = null;

            while (users.Count > 0)
            {
                foreach (var user in users)
                {
                    //block each user
                    if (user.UserId == lastUser?.UserId)
                        //doing refined search by last user's lastLogin can return same user since search
                        //is eventually consistent
                        //don't block same user again
                        continue;
                    await BlockUser(user);
                    blockedUsers++;
                }

                //save last user so we have their LastLogin/create time in case we need to refine search
                lastUser = users[users.Count - 1];
                //fetch next page

                //format last user's last_login or created_at date for search
                string refineDate;
                if (forUsersWithNoLogin)
                {
                    refineDate = ((DateTime)lastUser.CreatedAt).ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fff'Z'");
                }
                else
                {
                    refineDate = ((DateTime)lastUser.LastLogin).ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fff'Z'");
                }

                //get next batch of users to block.
                Console.WriteLine($"Refine search to look for users after {refineDate}");
                searchQuery = BuildUserSearchQuery(forUsersWithNoLogin, refineDate);
                users = await SearchUsers(searchQuery, forUsersWithNoLogin);
                if (users.Count == 1 && users[0].UserId == lastUser?.UserId)
                    //doing refined search by last user's lastLogin could return same user since search
                    //is eventually consistent.  If they are the only user returned we are done
                    users.Clear();

                Console.WriteLine($"Refined search found  {users.Count} new users.");
            }

            return blockedUsers;
        }

        /// <summary>
        /// Fetches an access token for the Auth0 Management api
        /// </summary>
        static async Task<TokenResponse> GetMgmtApiToken()
        {
            var client = new RestClient($"https://{GetConfigValue("A0Domain")}");
            var request = new RestRequest("/oauth/token", Method.POST);

            request.AddHeader("content-type", "application/json");
            request.AddParameter("application/json", $"{{\"client_id\":\"{GetConfigValue("ClientId")}\",\"client_secret\":\"{GetConfigValue("ClientSecret")}\",\"audience\":\"https://mattb.auth0.com/api/v2/\",\"grant_type\":\"client_credentials\"}}", ParameterType.RequestBody);

            var tokenResponse = await client.ExecuteTaskAsync<TokenResponse>(request);
            return tokenResponse.Data;
        }

        /// <summary>
        /// Builds the search string passed to the user search endpoints q param.
        /// </summary>
        static string BuildUserSearchQuery(bool forUsersWithNoLogin, string refineDate = "*")
        {
            var BlockThreshold = GetConfigValue("BlockThreshold");
            var BlockDate = DateTimeOffset.UtcNow.AddDays(double.Parse(BlockThreshold) * -1).ToString("yyyy-MM-dd");

            //Enchancement Option: The search could be narrowed to users in a specific connection by including:
            // identities.connection:"connection_name"
            if (forUsersWithNoLogin)
                // get unblocked users who have not logged in and whose created_at date was before blockdate
                return $"-last_login:[* TO *] AND created_at:[{refineDate} TO {BlockDate}] AND -blocked:true";
            else
            {
                // get unblocked users whose last login was before blockdate
                return $"last_login: [{refineDate} TO {BlockDate}] AND -blocked:true";
            }
        }

        /// <summary>
        /// Searches the management api for users to block
        /// </summary>
        static async Task<IPagedList<User>> SearchUsers(string searchQuery, bool forUsersWithNoLogin, string additionalFields = "")
        {
            var userRequest = new GetUsersRequest();

            userRequest.Fields = $"user_id,last_login,blocked,created_at{additionalFields}";
            userRequest.Query = searchQuery;
            userRequest.Sort = forUsersWithNoLogin ? "created_at:1" : "last_login:1";

            var pageInfo = new PaginationInfo(0, int.Parse(GetConfigValue("UserPageSize")), true);

            try
            {
                Console.WriteLine($"Fetching users. query: {searchQuery}.");
                return await MgmtClient.Users.GetAllAsync(userRequest, pageInfo);
            }
            catch (ApiException e)
            {
                if (e.StatusCode == HttpStatusCode.TooManyRequests)
                {
                    //update failed due to mgmt api rate limits.  Try one more time after delay.
                    await PauseForRateLimitReset(MgmtClient.GetLastApiInfo());
                    Console.WriteLine($"Fetching users. query: {searchQuery}. ");
                    return await MgmtClient.Users.GetAllAsync(userRequest, pageInfo);
                }
                throw;
            }
        }


        /// <summary>
        /// Calls the management api to block/unblock the provided user.
        /// </summary>        
        static async Task BlockUser(User user, bool blocked = true)
        {

            Console.WriteLine($"{(blocked ? "Blocking" : "Unblocking")}: {user.UserId}. Last Login: {user.LastLogin}. Created At: {user.CreatedAt}");
            try
            {
                await MgmtClient.Users.UpdateAsync(user.UserId, new UserUpdateRequest { Blocked = blocked });
                await ApplyThrottle(MgmtClient.GetLastApiInfo());
            }
            catch (ApiException e)
            {
                if (e.StatusCode == HttpStatusCode.TooManyRequests)
                {
                    //update failed due to mgmt api rate limits.  Try one more time after delay.
                    await PauseForRateLimitReset(MgmtClient.GetLastApiInfo());
                    await MgmtClient.Users.UpdateAsync(user.UserId, new UserUpdateRequest { Blocked = blocked });
                }
            }
        }

        /// <summary>
        /// Checks if the mgmt api rate limit remaining response is below a certain threshold and if so
        /// delays until limit has refreshed.  Prevents the process from consuming all available mgmt api calls.
        /// </summary>   
        static async Task ApplyThrottle(ApiInfo info)
        {
            if (info.RateLimit.Remaining < int.Parse(GetConfigValue("RateLimitThrottle")))
            {
                await PauseForRateLimitReset(info);
            }
        }

        /// <summary>
        /// Pauses until the mgmt api rate limit reset time has passed.
        /// </summary>  
        static async Task PauseForRateLimitReset(ApiInfo info)
        {
            var remaining = info.RateLimit.Remaining;
            var reset = info.RateLimit.Reset;
            var limit = info.RateLimit.Limit;

            Console.WriteLine($"Rate Limit ({limit}) hit at {DateTimeOffset.UtcNow}, {remaining} remaining. Pausing until {reset}");

            var delay = (int)(reset - DateTimeOffset.UtcNow).TotalMilliseconds;
            await Task.Delay(delay > 0 ? delay : 0);
            Console.WriteLine($"Resuming mgmt api calls after delay of {delay}.");
        }

        /// <summary>
        /// Fetches the value for the specified key from appsettings
        /// </summary>
        static string GetConfigValue(string key)
        {
            return configuration.GetSection(key)?.Value;
        }
    }
}
