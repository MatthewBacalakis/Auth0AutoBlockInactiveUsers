using System;
using System.Threading.Tasks;
using Auth0.AuthenticationApi;
using Auth0.AuthenticationApi.Models;
using Auth0.ManagementApi;
using Auth0.ManagementApi.Models;
using Auth0.ManagementApi.Paging;
using Auth0.Core.Exceptions;
using Microsoft.Extensions.Configuration;
using System.IO;


namespace AutomatedBlockUsers
{
    class Program
    {
        enum SearchCriteria
        {
            Login,
            UserCreation
        }

        static IConfigurationRoot configuration;
        static ManagementApiClient MgmtClient;

        static async Task Main(string[] args)
        {
            //setup pulling config from appsettings.json
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true);
            configuration = builder.Build();

            var auth0AuthClient = new AuthenticationApiClient(GetConfigValue("A0Domain"));

            //get token to call mgmt api
            var token = (await GetMgmtApiToken(auth0AuthClient)).AccessToken;

            MgmtClient = new ManagementApiClient(token, GetConfigValue("A0Domain"));

            //for test purposes: run utility with param of "-u" to unblock 1 page of users after testing
            #region unblock users
            if (args.Length > 0 && args[0] == "-u")
            {
                int count = 0;
                var allUsers = await SearchUsers(string.Empty, SearchCriteria.UserCreation, ",blocked");
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
            int usersBlockedByLogin = await BlockUsers(SearchCriteria.Login);
            Console.WriteLine($"Blocked {usersBlockedByLogin} users based on last_login.");
            Console.WriteLine();

            //block users who have never logged in based on create date.
            int usersBlockedByCreate = await BlockUsers(SearchCriteria.UserCreation);
            Console.WriteLine($"Blocked {usersBlockedByLogin} users based on last_login.");
            Console.WriteLine($"Blocked {usersBlockedByCreate} users based on created_at.");
            Console.WriteLine($"Blocked {usersBlockedByLogin + usersBlockedByCreate} users in total");
        }


        /// <summary>
        /// Identifies and blocks all users based either on last_login or create date if user has never logged in
        /// as indicated by bool param
        /// </summary>
        static async Task<int> BlockUsers(SearchCriteria searchCriteria)
        {
            //build search query to fetch first (up to) 100 applicable users
            var searchQuery = BuildUserSearchQuery(searchCriteria);

            //fetch users that match initial query
            var users = await SearchUsers(searchQuery, searchCriteria);

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

                //save last user so we have their LastLogin/create time to refine search
                lastUser = users[users.Count - 1];
                //fetch next page

                //format last user's last_login or created_at date for search
                string refineDate;
                var unformatedDate = searchCriteria == SearchCriteria.UserCreation ? lastUser.CreatedAt : lastUser.LastLogin;
                refineDate = ((DateTime)unformatedDate).ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fff'Z'");

                //get next batch of users to block.
                Console.WriteLine($"Refine search to look for users after {refineDate}");
                searchQuery = BuildUserSearchQuery(searchCriteria, refineDate);
                users = await SearchUsers(searchQuery, searchCriteria);
                if (users.Count == 1 && users[0].UserId == lastUser?.UserId)
                    //doing refined search by last user's lastLogin could return same user since search
                    //is eventually consistent.  If they are the only user returned we are done
                    users.Clear();

                Console.WriteLine($"Refined search found  {users.Count} new users.");
            }

            return blockedUsers;
        }

        // <summary>
        // Fetches an access token for the Auth0 Management api
        // </summary>
        static Task<AccessTokenResponse> GetMgmtApiToken(AuthenticationApiClient authClient)
        {
            var request = new ClientCredentialsTokenRequest()
            {
                Audience = $"https://{GetConfigValue("A0Domain")}/api/v2/",
                ClientId = GetConfigValue("ClientId"),
                ClientSecret = GetConfigValue("ClientSecret")
            };
            return authClient.GetTokenAsync(request);
        }

        /// <summary>
        /// Builds the search string passed to the user search endpoints q param.
        /// </summary>
        static string BuildUserSearchQuery(SearchCriteria searchCriteria, string refineDate = "*")
        {
            var BlockThreshold = GetConfigValue("BlockThreshold");
            var BlockDate = DateTimeOffset.UtcNow.AddDays(double.Parse(BlockThreshold) * -1).ToString("yyyy-MM-dd");


            if (searchCriteria == SearchCriteria.UserCreation)
                // get unblocked users who have not logged in and whose created_at date was before blockdate
                return $"identities.connection:{GetConfigValue("ConnectionName")} AND -last_login:[* TO *] AND created_at:[{refineDate} TO {BlockDate}] AND -blocked:true";
            else
            {
                // get unblocked users whose last login was before blockdate
                return $"identities.connection:{GetConfigValue("ConnectionName")} AND last_login: [{refineDate} TO {BlockDate}] AND -blocked:true";
            }
        }

        /// <summary>
        /// Searches the management api for users to block
        /// </summary>
        static async Task<IPagedList<User>> SearchUsers(string searchQuery, SearchCriteria searchCriteria, string additionalFields = "")
        {
            var userRequest = new GetUsersRequest();

            userRequest.Fields = $"user_id,last_login,blocked,created_at{additionalFields}";
            userRequest.Query = searchQuery;
            userRequest.Sort = searchCriteria == SearchCriteria.UserCreation ? "created_at:1" : "last_login:1";

            var pageInfo = new PaginationInfo(0, int.Parse(GetConfigValue("UserPageSize")), true);

            try
            {
                Console.WriteLine($"Fetching users. query: {searchQuery}.");
                return await MgmtClient.Users.GetAllAsync(userRequest, pageInfo);
            }
            catch (ApiException e)
            {
                Console.WriteLine(e);
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

            }
            catch (ApiException e)
            {
                Console.WriteLine(e);
                throw;
            }
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
