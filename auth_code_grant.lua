-- Copyright 2024 Snap One, LLC. All rights reserved.

AUTH_CODE_GRANT_VER = 31

require ('drivers-common-public.global.lib')
require ('drivers-common-public.global.url')
require ('drivers-common-public.global.timer')

pcall (require, 'drivers-common-public.global.make_short_link')

Metrics = require ('drivers-common-public.module.metrics')

--- Holds OAuth functionality.
local oauth = {}

--- Creates a new OAuth object.
--- @param tParams Table containing the OAuth parameters.
--- @param providedRefreshToken Optional refresh token to use.
--- @return The new OAuth object.
--- @return Whether or not a refresh event will be generated.
function oauth:new (tParams, providedRefreshToken)
    -- CONFIGURE A NEW OAUTH OBJECT WITH THE PROVIDED PARAMETERS.
    local newOAuth = {
        NAME = tParams.NAME,
        AUTHORIZATION = tParams.AUTHORIZATION,

        SHORT_LINK_AUTHORIZATION = tParams.SHORT_LINK_AUTHORIZATION,
        LINK_CHANGE_CALLBACK = tParams.LINK_CHANGE_CALLBACK,

        REDIRECT_URI = tParams.REDIRECT_URI,
        AUTH_ENDPOINT_URI = tParams.AUTH_ENDPOINT_URI,
        TOKEN_ENDPOINT_URI = tParams.TOKEN_ENDPOINT_URI,

        REDIRECT_DURATION = tParams.REDIRECT_DURATION,

        API_CLIENT_ID = tParams.API_CLIENT_ID,
        API_SECRET = tParams.API_SECRET,

        SCOPES = tParams.SCOPES,

        TOKEN_HEADERS = tParams.TOKEN_HEADERS,

        USE_PKCE = tParams.USE_PKCE,

        MAX_EXPIRES_IN = tParams.MAX_EXPIRES_IN or 86400,           -- one day
        DEFAULT_EXPIRES_IN = tParams.DEFAULT_EXPIRES_IN or 3600,    -- one hour

        notifyHandler = {},
        Timer = {},
    }

    -- CONFIGURE BASIC AUTHORIZATION HEADERS IF APPLICABLE.
    if (tParams.USE_BASIC_AUTH_HEADER) then
        newOAuth.BasicAuthHeader = 'Basic ' .. C4:Base64Encode (tParams.API_CLIENT_ID .. ':' .. tParams.API_SECRET)
    end

    -- CONFIGURE THE NEW OAUTH OBJECT TO HAVE DEFAULT OAUTH TABLE PROPERTIES.
    setmetatable (newOAuth, self)
    self.__index = self

    -- INITIALIE OAUTH METRICS.
    newOAuth.metrics = Metrics:new ('dcp_auth_code', AUTH_CODE_GRANT_VER, (newOAuth.NAME or newOAuth.API_CLIENT_ID))

    -- TRY TO GET AN INITIAL REFRESH TOKEN.
    local initialRefreshToken
    -- If a refresh token was provided, that should take precedence.
    if (providedRefreshToken) then
        initialRefreshToken = providedRefreshToken
    else
        -- TRY GETTING AN ENCRYPTED TOKEN FROM A PERSISTENT KEY STORE.
        local persistStoreKey = C4:Hash ('SHA256', C4:GetDeviceID () .. newOAuth.API_CLIENT_ID, SHA_ENC_DEFAULTS)
        local encryptedToken = PersistGetValue (persistStoreKey)
        if (encryptedToken) then
            -- DECRYPT THE ENCRYPTED TOKEN.
            local encryptionKey = C4:GetDeviceID () .. newOAuth.API_SECRET .. newOAuth.API_CLIENT_ID
            local refreshToken, errorMessage = SaltedDecrypt (encryptionKey, encryptedToken)

            -- CHECK IF DECRYPTION ERRORS OCCURRED.
            if (errorMessage) then
                -- TRACK THAT DECRYPTING THE REFRESH TOKEN FAILED.
                newOAuth.metrics:SetString ('Error_DecryptRefreshToken', errorMessage)
            end
                -- USE THE DECRYPTED REFRESH TOKEN IF IT EXISTS.
                if (refreshToken) then
                initialRefreshToken = refreshToken
            end
        end
    end

    -- CHECK IF AN INITIAL REFRESH TOKEN COULD BE FOUND.
    if (initialRefreshToken) then
        -- TRACK THE OAUTH INSTANCE BEING INITIALIZED WITH A TOKEN.
        newOAuth.metrics:SetCounter ('InitWithToken')

        -- CONFIGURE A TIMER TO REFRESH THE TOKEN AFTER AN APPROPRIATE INTERVAL.
        local _timer = function (timer)
            local NO_CONTEXT = nil
            newOAuth:RefreshToken (NO_CONTEXT, initialRefreshToken)
        end
        local NO_TIMER_ID = nil
        SetTimer (NO_TIMER_ID, ONE_SECOND, _timer)
    else
        -- TRACK THE OAUTH INSTANCE BEING INITIALIZED WITHOUT A TOKEN.
        newOAuth.metrics:SetCounter ('InitWithoutToken')
    end

    -- CHECK IF A REFRESH EVENT WILL BE GENERATED.
    local willGenerateRefreshEvent = (initialRefreshToken ~= nil)

    -- RETURN THE NEW OAUTH OBJECT AND WHETHER A REFRESH EVENT WILL BE GENERATED.
    return newOAuth, willGenerateRefreshEvent
end

--- Attempts to make OAuth state.
--- @param contextInfo Context information.
--- @param extraParamsForAuthLink Extra parameters for the authorization link.
--- @param uriToCompletePage URI to redirect to for completion.
function oauth:MakeState (contextInfo, extraParamsForAuthLink, uriToCompletePage)
    -- ENSURE CONTEXT EXISTS.
    if (type (contextInfo) ~= 'table') then
        contextInfo = {}
    end

    -- GENERATE A RANDOM STATE VALUE.
    local state = GetRandomString (50)

    -- CREATE THE URL WITH REDIRECT AND STATE PARAMETERS.
    local url = MakeURL (self.REDIRECT_URI .. 'state')

    -- DEFINE APPROPRIATE AUTHORIZATION HEADERS FOR THE REQUEST.
    local headers = {
        Authorization = self.AUTHORIZATION,
    }

    -- COMBINE ALL DATA NEEDED FOR THE POST REQUEST.
    local data = {
        duration = self.REDIRECT_DURATION,
        clientId = self.API_CLIENT_ID,
        authEndpointURI = self.AUTH_ENDPOINT_URI,
        state = state,
        redirectURI = uriToCompletePage,
    }

    -- COMBINE ALL OF THE CONTEXT FOR THE REQUEST.
    local context = {
        contextInfo = contextInfo,
        state = state,
        extraParamsForAuthLink = extraParamsForAuthLink
    }

    -- TRY MAKING THE STATE REQUEST.
    -- A callback will handle the response.
    self.metrics:SetCounter ('MakeStateAttempt')
    self:urlPost (url, data, headers, 'MakeStateResponse', context)
end

--- Handles the response from making OAuth state.
--- @param errorMessage Any error message from the response.
--- @param responseCode The response code from the request.
--- @param tHeaders The headers from the response.
--- @param data The data from the response.
--- @param context The context from the request.
--- @param url The URL of the request.
function oauth:MakeStateResponse (errorMessage, responseCode, tHeaders, data, context, url)
    -- CHECK IF AN ERROR OCCURRED.
    if (errorMessage) then
        -- LOG THE ERROR FOR DEBUGGING.
        -- Nothing more can be done if an error occurred.
        dbg ('Error with MakeState', errorMessage)
        return
    end

    -- GET THE CONTEXT INFO FROM THE ORIGINAL REQUEST.
    local contextInfo = context.contextInfo

    -- CHECK IF THE MAKE STATE RESPONSE WAS SUCCESSFUL.
    if (responseCode == 200) then
        -- TRACK THE SUCCESSFUL STATE CREATION.
        self.metrics:SetCounter ('MakeStateSuccess')

        -- CONFIGURE A TIMER TO CHECK IF THE ACTIVATION HAS TIMED OUT.
        local expiresAt = data.expiresAt or (os.time () + self.REDIRECT_DURATION)
        local timeRemaining = expiresAt - os.time ()
        local _timedOut = function (timer)
            -- STOP THE TIMER FOR PERIODICALLY CHECKING THE STATE.
            CancelTimer (self.Timer.CheckState)

            -- CLEAR THE LINK.
            self:setLink ('')

            -- TRACK THE TIME OUT.
            self.metrics:SetCounter ('ActivationTimeOut')
            self:notify ('ActivationTimeOut', contextInfo)
        end

        self.Timer.GetCodeStatusExpired = SetTimer (self.Timer.GetCodeStatusExpired, timeRemaining * ONE_SECOND, _timedOut)

        -- SET A REPEATING TIMER TO CHECK THE OAUTH STATE.
        local state = context.state
        local nonce = data.nonce
        local _timer = function (timer)
            self:CheckState (state, contextInfo, nonce)
        end
        self.Timer.CheckState = SetTimer (self.Timer.CheckState, 5 * ONE_SECOND, _timer, true)

        -- GET THE LINK CODE.
        local extraParamsForAuthLink = context.extraParamsForAuthLink
        self:GetLinkCode (state, contextInfo, extraParamsForAuthLink)
    end
end

--- Gets an OAuth link code.
--- @param state The state to use for the link code.
--- @param contextInfo Context information.
--- @param extraParamsForAuthLink Extra parameters for the authorization link.
function oauth:GetLinkCode (state, contextInfo, extraParamsForAuthLink)
    -- ENSURE CONTEXT EXISTS.
    if (type (contextInfo) ~= 'table') then
        contextInfo = {}
    end

    -- ENSURE SCOPES ARE APPROPRIATELY DEFINED.
    -- Scopes may optionally be configured for this OAuth instance.
    local scope
    if (self.SCOPES) then
        -- CONVERT SCOPES TO A STRING IF NEEDED.
        if (type (self.SCOPES) == 'table') then
            scope = table.concat (self.SCOPES, ' ')
        elseif (type (self.SCOPES) == 'string') then
            scope = self.SCOPES
        end
    end

    -- DEFINE BASE ARGUMENTS FOR THE LINK.
    local arguments = {
        client_id = self.API_CLIENT_ID,
        response_type = 'code',
        redirect_uri = self.REDIRECT_URI .. 'callback',
        state = state,
        scope = scope,
    }

    -- CONFIGURE PROOF-KEY-FOR-CODE-EXCHANGE IF APPLICABLE.
    if (self.USE_PKCE) then
        -- GENERATE A RANDOM CODE VERIFIER.
        self.code_verifier = GetRandomString (128)

        -- DEFINE THE CODE CHALLENGE URL.
        -- The code challenge needs to be hashed, base64-encoded, and URL encoded.
        local code_challenge = C4:Hash ('SHA256', self.code_verifier, SHA_ENC_DEFAULTS)
        local code_challenge_b64 = C4:Base64Encode (code_challenge)
        local code_challenge_b64_url = code_challenge_b64:gsub ('%+', '-'):gsub ('%/', '_'):gsub ('%=', '')

        -- ADD ARGUMENTS FOR THE CODE CHALLENGE.
        arguments.code_challenge = code_challenge_b64_url
        arguments.code_challenge_method = 'S256'
    end

    -- ADD ANY EXTRA PARAMETERS FOR THE AUTHORIZATION LINK.
    local extraParamsForAuthorizationLinkValid = (extraParamsForAuthLink and type (extraParamsForAuthLink) == 'table')
    if (extraParamsForAuthorizationLinkValid) then
        for parameterKey, parameterValue in pairs (extraParamsForAuthLink) do
            arguments [parameterKey] = parameterValue
        end
    end

    -- MAKE THE AUTHORIZATION LINK URL USING THE ARGUMENTS.
    local link = MakeURL (self.AUTH_ENDPOINT_URI, arguments)

    -- CHECK IF A SHORT LINK SHOULD BE USED.
    local useShortLink = (self.SHORT_LINK_AUTHORIZATION and MakeShortLink)
    if (useShortLink) then
        -- MAKE A SHORT LINK.
        -- Once the link is made, a callback is used to set the link.
        local _linkCallback = function (shortLink)
            self:setLink (shortLink, contextInfo)
        end
        MakeShortLink (link, _linkCallback, self.SHORT_LINK_AUTHORIZATION)
    else
        -- SET THE LINK.
        self:setLink (link, contextInfo)
    end
end

--- Checks the OAuth state.
--- @param state The state to check.
--- @param contextInfo Context information.
--- @param nonce The nonce for the request.
function oauth:CheckState (state, contextInfo, nonce)
    -- ENSURE CONTEXT EXISTS.
    if (type (contextInfo) ~= 'table') then
        contextInfo = {}
    end

    -- CHECK THE STATE AT THE APPROPRIATE URL.
    -- A callback will handle the response.
    local url = MakeURL (self.REDIRECT_URI .. 'state', {state = state, nonce = nonce})
    local NO_HEADERS = nil
    self:urlGet (url, NO_HEADERS, 'CheckStateResponse', {state = state, contextInfo = contextInfo})
end

--- Handles the response from checking the OAuth state.
--- @param errorMessage Any error message from the response.
--- @param responseCode The response code from the request.
--- @param tHeaders The headers from the response.
--- @param data The data from the response.
--- @param context The context from the request.
--- @param url The URL of the request.
function oauth:CheckStateResponse (errorMessage, responseCode, tHeaders, data, context, url)
    if (errorMessage) then
        -- LOG THE ERROR FOR DEBUGGING.
        -- Nothing more can be done if an error occurred.
        dbg ('Error with CheckState:', errorMessage)
        return
    end

    -- GET THE CONTEXT INFO FROM THE ORIGINAL REQUEST.
    local contextInfo = context.contextInfo

    -- HANDLE THE RESPONSE APPROPRIATELY DEPENDING ON THE CODE.
    if (responseCode == 200 and data.code) then
        -- state exists and has been authorized

        -- CANCEL TIMERS.
        CancelTimer (self.Timer.CheckState)
        CancelTimer (self.Timer.GetCodeStatusExpired)

        -- TRACK THE LINK CODE AS BEING CONFIRMED.
        self.metrics:SetCounter ('LinkCodeConfirmed')
        self:notify ('LinkCodeConfirmed', contextInfo, data.code)

        -- GET THE USER TOKEN IF A TOKEN ENDPOINT URI EXISTS.
        if (self.TOKEN_ENDPOINT_URI) then
            self:GetUserToken (data.code, contextInfo)
        end

    elseif (responseCode == 204) then
        -- TRACK STILL WAITING FOR THE LINK CODE.
        self:notify ('LinkCodeWaiting', contextInfo)

    elseif (responseCode == 401) then
        -- nonce value incorrect or missing for this state

        -- CANCEL TIMERS.
        CancelTimer (self.Timer.CheckState)
        CancelTimer (self.Timer.GetCodeStatusExpired)

        -- CLEAR THE LINK.
        self:setLink ('')

        -- TRACK THE LINK CODE ERROR.
        self.metrics:SetCounter ('LinkCodeError')
        self:notify ('LinkCodeError', contextInfo)

    elseif (responseCode == 403) then
        -- state exists and has been denied authorization by the service

        -- CANCEL TIMERS.
        CancelTimer (self.Timer.CheckState)
        CancelTimer (self.Timer.GetCodeStatusExpired)

        -- CLEAR THE LINK.
        self:setLink ('')

        -- TRACK THE DENIAL.
        self.metrics:SetCounter ('LinkCodeDenied')
        -- If an error reason exists, it can be further tracked.
        if (data.error) then
            self.metrics:SetString ('LinkCodeDeniedReason', data.error)
        end
        -- If an error description exists, it can be further tracked.
        if (data.error_description) then
            self.metrics:SetString ('LinkCodeDeniedDescription', data.error_description)
        end
        self:notify ('LinkCodeDenied', contextInfo, data.error, data.error_description, data.error_uri)

    elseif (responseCode == 404) then
        -- state doesn't exist

        -- CANCEL TIMERS.
        CancelTimer (self.Timer.CheckState)
        CancelTimer (self.Timer.GetCodeStatusExpired)

        -- CLEAR THE LINK.
        self:setLink ('')

        -- TRACK THE LINK CODE EXPIRING.
        self.metrics:SetCounter ('LinkCodeExpired')
        self:notify ('LinkCodeExpired', contextInfo)
    end
end

--- Gets a user token.
--- @param code The code to use for the user token.
--- @param contextInfo Context information.
function oauth:GetUserToken (code, contextInfo)
    -- ENSURE CONTEXT EXISTS.
    if (type (contextInfo) ~= 'table') then
        contextInfo = {}
    end

    -- CHECK IF A CODE EXISTS.
    if (code) then
        -- DEFINE ARGUMENTS FOR THE TOKEN REQUEST.
        local arguments = {
            client_id = self.API_CLIENT_ID,
            client_secret = self.API_SECRET,
            grant_type = 'authorization_code',
            code = code,
            redirect_uri = self.REDIRECT_URI .. 'callback',
        }

        -- Proof-key-for-code-exchange may optionally be configured.
        if (self.USE_PKCE) then
            -- ENSURE THE CODE VERIFIER IS SPECIFIED.
            arguments.code_verifier = self.code_verifier
        end

        -- DEFINE THE DATA FOR THE TOKEN REQUEST.
        local NO_DATA_URL_PATH = nil
        local data = MakeURL (NO_DATA_URL_PATH, arguments)

        -- DEFINE HEADERS FOR THE TOKEN REQUEST.
        local headers = {
            ['Content-Type'] = 'application/x-www-form-urlencoded',
            ['Authorization'] = self.BasicAuthHeader,
        }

        -- Additional token headers can be added.
        local tokenHeadersValid = (self.TOKEN_HEADERS and type (self.TOKEN_HEADERS == 'table'))
        if (tokenHeadersValid) then
            -- ADD EACH TOKEN HEADER.
            for token_header_key, token_header_value in pairs (self.TOKEN_HEADERS) do
                -- ONLY ADD A TOKEN HEADER IF IT HASN'T ALREADY BEEN SET.
                if (not (headers [token_header_key])) then
                    headers [token_header_key] = token_header_value
                end
            end
        end

        -- MAKE THE TOKEN REQUEST.
        -- A callback will handle the response.
        local url = self.TOKEN_ENDPOINT_URI
        self:urlPost (url, data, headers, 'GetTokenResponse', {contextInfo = contextInfo})
    end
end

--- Refreshes an OAuth token.
--- @param contextInfo Context information.
--- @param newRefreshToken The new refresh token to use, if desired.
function oauth:RefreshToken (contextInfo, newRefreshToken)
    -- SET A NEW REFRESH TOKEN IF SPECIFIED.
    if (newRefreshToken) then
        self.REFRESH_TOKEN = newRefreshToken
    end

    -- CHECK IF A REFRESH TOKEN EXISTS.
    local refreshTokenMissing = (self.REFRESH_TOKEN == nil)
    if (refreshTokenMissing) then
        -- No token can be refreshed if one doesn't exist.
        self.metrics:SetCounter ('NoRefreshToken')
        return false
    end

    -- CHECK IF THE TOKEN IS ALREADY BEING REFRESHED.
    if (self.Timer.RefreshingToken) then
        -- Track avoiding a collision.
        self.metrics:SetCounter ('CollisionAvoided')
        return
    end

    -- ENSURE CONTEXT EXISTS.
    if (type (contextInfo) ~= 'table') then
        contextInfo = {}
    end

    -- DEFINE ARGUMENTS FOR THE REFRESH TOKEN REQUEST.
    local arguments = {
        refresh_token = self.REFRESH_TOKEN,
        client_id = self.API_CLIENT_ID,
        client_secret = self.API_SECRET,
        grant_type = 'refresh_token',
    }

    -- DEFINE THE DATA FOR THE REFRESH TOKEN REQUEST.
    local NO_DATA_URL_PATH = nil
    local data = MakeURL (NO_DATA_URL_PATH, arguments)

    -- DEFINE HEADERS FOR THE REFRESH TOKEN REQUEST.
    local headers = {
        ['Content-Type'] = 'application/x-www-form-urlencoded',
        ['Authorization'] = self.BasicAuthHeader,
    }

    -- Additional token headers can be added.
    local tokenHeadersValid = (self.TOKEN_HEADERS and type (self.TOKEN_HEADERS == 'table'))
    if (tokenHeadersValid ) then
        -- ADD EACH TOKEN HEADER.
        for token_header_key, token_header_value in pairs (self.TOKEN_HEADERS) do
            -- ONLY ADD A TOKEN HEADER IF IT HASN'T ALREADY BEEN SET.
            if (not (headers [token_header_key])) then
                headers [token_header_key] = token_header_value
            end
        end
    end

    -- CREATE A TIMER FOR REFRESHING THE TOKEN.
    local _timer = function (timer)
        self.metrics:SetCounter ('CollisionAvoidanceTimerExpired')
        self.Timer.RefreshingToken = self.Timer.RefreshingToken:Cancel ()
        self:RefreshToken ()
    end
    self.Timer.RefreshingToken = SetTimer (self.Timer.RefreshingToken, 30 * ONE_SECOND, _timer)

    -- MAKE THE TOKEN REQUEST.
    -- A callback will handle the response.
    local url = self.TOKEN_ENDPOINT_URI
    self:urlPost (url, data, headers, 'GetTokenResponse', {contextInfo = contextInfo})
end

--- Handles a response related to an OAuth token request.
--- @param errorMessage Any error message from the response.
--- @param responseCode The response code from the request.
--- @param tHeaders The headers from the response.
--- @param data The data from the response.
--- @param context The context from the request.
--- @param url The URL of the request.
function oauth:GetTokenResponse (errorMessage, responseCode, tHeaders, data, context, url)
    -- CANCEL ANY TOKEN REFRESH TIMER.
    if (self.Timer.RefreshingToken) then
        self.Timer.RefreshingToken = self.Timer.RefreshingToken:Cancel ()
    end

    -- CHECK IF AN ERROR OCCURRED.
    if (errorMessage) then
        -- LOG THE ERROR FOR DEBUGGING.
        dbg ('Error with GetToken:', errorMessage)

        -- CREATE A TIMER FOR REFRESHING THE TOKEN.
        local _timer = function (timer)
            self:RefreshToken ()
        end
        self.Timer.RefreshToken = SetTimer (self.Timer.RefreshToken, 30 * ONE_SECOND, _timer)
        return
    end

    -- GET THE CONTEXT INFO FROM THE ORIGINAL REQUEST.
    local contextInfo = context.contextInfo

    -- HANDLE THE RESPONSE APPROPRIATELY DEPENDING ON THE CODE.
    local tokenResponseSuccessful = (responseCode == 200)
    local tokenResponseErrorOccurred = (responseCode >= 400 and responseCode < 500)
    if (tokenResponseSuccessful) then
        -- UPDATE THE TOKENS BASED ON THE RESPONSE DATA.
        self.ACCESS_TOKEN = data.access_token
        self.REFRESH_TOKEN = data.refresh_token or self.REFRESH_TOKEN

        -- STORE THE TOKEN AS ENCRYPTED IF POSSIBLE.
        local persistStoreKey = C4:Hash ('SHA256', C4:GetDeviceID () .. self.API_CLIENT_ID, SHA_ENC_DEFAULTS)

        local encryptionKey = C4:GetDeviceID () .. self.API_SECRET .. self.API_CLIENT_ID
        local encryptedToken, errString = SaltedEncrypt (encryptionKey, self.REFRESH_TOKEN)
        if (errString) then
            self.metrics:SetString ('Error_EncryptRefreshToken', errString)
        end

        PersistSetValue (persistStoreKey, encryptedToken)

        -- UPDATE THE SCOPE BASED ON THE RESPONSE DATA.
        self.SCOPE = data.scope or self.SCOPE

        -- UPDATE THE EXPIRATION TIME BASED ON THE RESPONSE DATA.
        self.EXPIRES_IN = tonumber(data.expires_in) or self.EXPIRES_IN or self.DEFAULT_EXPIRES_IN

        -- SET A TIMER TO REFRESH EXPIRING TOKENS IF APPLICABLE.
        local tokensExpireAndCanBeRefreshed = (self.EXPIRES_IN and self.REFRESH_TOKEN)
        if (tokensExpireAndCanBeRefreshed) then
            -- CAP THE EXPIRATION TIME TO WITHIN A MAX VALUE.
            local expirationTimeTooLarge = (self.EXPIRES_IN > self.MAX_EXPIRES_IN)
            if (expirationTimeTooLarge) then
                self.metrics:SetCounter ('ShortenedExpiryTime')
                self.EXPIRES_IN_ORIGINAL = self.EXPIRES_IN
                self.EXPIRES_IN = self.MAX_EXPIRES_IN
            end

            -- CREATE THE TIMER FOR REFRESHING THE TOKEN.
            -- Spread out refreshing the token to avoid all tokens across entire system being refreshed at the same time.
            local delay = self.EXPIRES_IN * math.random (750, 950)
            local _timer = function (timer)
                self:RefreshToken ()
            end
            self.Timer.RefreshToken = SetTimer (self.Timer.RefreshToken, delay, _timer)
        end

        -- LOG THE TOKEN BEING RECEIVED.
        print ((self.NAME or 'OAuth') .. ': Access Token received, accessToken:' .. tostring (self.ACCESS_TOKEN ~= nil) .. ', refreshToken:' .. tostring (self.REFRESH_TOKEN ~= nil))

        -- CLEAR THE LINK.
        self:setLink ('')

        -- TRACK THE TOKEN BEING GRANTED.
        self.metrics:SetCounter ('AccessTokenGranted')
        self:notify ('AccessTokenGranted', contextInfo, self.ACCESS_TOKEN, self.REFRESH_TOKEN)

    elseif (tokenResponseErrorOccurred) then
        -- CLEAR THE TOKENS.
        self.ACCESS_TOKEN = nil
        self.REFRESH_TOKEN = nil

        -- CLEAR THE PERSISTENTLY STORED TOKEN KEY.
        local persistStoreKey = C4:Hash ('SHA256', C4:GetDeviceID () .. self.API_CLIENT_ID, SHA_ENC_DEFAULTS)
        PersistDeleteValue (persistStoreKey)

        -- LOG THE TOKEN BEING DENIED.
        print ((self.NAME or 'OAuth') .. ': Access Token denied:', data.error, data.error_description, data.error_uri)

        -- CLEAR THE LINK.
        self:setLink ('')

        -- TRACK THE TOKEN BEING DENIED.
        self.metrics:SetCounter ('AccessTokenDenied')
        -- If an error reason exists, it can be further tracked.
        if (data.error) then
            self.metrics:SetString ('AccessTokenDeniedReason', data.error)
        end
        -- If an error description exists, it can be further tracked.
        if (data.error_description) then
            self.metrics:SetString ('AccessTokenDeniedDescription', data.error_description)
        end
        self:notify ('AccessTokenDenied', contextInfo, data.error, data.error_description, data.error_uri)
    end
end

--- Deletes the refresh token.
function oauth:DeleteRefreshToken ()
    -- CHECK IF A REFRESH TOKEN EXISTS.
    local existed = (self.REFRESH_TOKEN ~= nil)

    -- CLEAR ANY TOKENS (INCLUDING THOSE PERSISTENTLY STORED).
    local persistStoreKey = C4:Hash ('SHA256', C4:GetDeviceID () .. self.API_CLIENT_ID, SHA_ENC_DEFAULTS)
    PersistDeleteValue (persistStoreKey)
    self.ACCESS_TOKEN = nil
    self.REFRESH_TOKEN = nil

    -- CANCEL THE TOKEN REFRESH TIMER.
    self.Timer.RefreshToken = CancelTimer (self.Timer.RefreshToken)

    -- TRACK THE REFRESH TOKEN BEING DELETED.
    self.metrics:SetCounter ('RefreshTokenDeleted')
    local NO_CONTEXT = nil
    self:notify ('RefreshTokenDeleted', NO_CONTEXT, existed)
end

--- Sets the link code.
--- @param link The link code to set.
--- @param contextInfo Context information.
function oauth:setLink (link, contextInfo)
    -- COUNT A LINK CODE IF RECEIVED.
    local linkCodeReceived = (link ~= '')
    if (linkCodeReceived) then
        self.metrics:SetCounter ('LinkCodeReceived')
    end
    self:notify ('LinkCodeReceived', contextInfo, link)

    -- CALL A LINK CHANGE CALLBACK IF APPLICABLE.
    local linkChangeCallbackExists = (self.LINK_CHANGE_CALLBACK and type (self.LINK_CHANGE_CALLBACK) == 'function')
    if (linkChangeCallbackExists ) then
        -- CALL THE LINK CHANGE CALLBACK.
        local success, linkChangeCallbackReturnCode = pcall (self.LINK_CHANGE_CALLBACK, link, contextInfo)

        -- LOG AN ERROR IF CALLING THE LINK CHANGE CALLBACK FAILED.
        if (success == false) then
            print ((self.NAME or 'OAuth') .. ':LINK_CHANGE_CALLBACK Lua error: ', link, linkChangeCallbackReturnCode)
        end
    end
end

--- Notifies an OAuth handler.
--- @param handlerName The name of the handler to notify.
--- @param contextInfo Context information.
--- @param ... Additional arguments to pass to the handler.
function oauth:notify (handlerName, contextInfo, ...)
    -- CHECK IF THE HANDLER IS VALID.
    local handlerValid = self.notifyHandler [handlerName] and type (self.notifyHandler [handlerName]) == 'function'
    if (handlerValid) then
        -- CALL THE HANDLER WITH THE APPROPRIATE CONTEXT.
        local success, handlerReturnCode = pcall (self.notifyHandler [handlerName], contextInfo, ...)

        -- LOG AN ERROR IF CALLING THE HANDLER FAILED.
        if (success == false) then
            print ((self.NAME or 'OAuth') .. ':' .. handlerName .. ' Lua error: ', handlerReturnCode, ...)
        end
    end
end

--- Perform an OAuth request.
--- @param method HTTP method to use (e.g. "GET", "POST", etc.).
--- @param url URL to send the request to.
--- @param data Data to be sent with the request.
--- @param headers HTTP headers to be sent with the request.
--- @param callback Callback function to be called with the response.
--- @param context Context to be passed to the callback function.
function oauth:urlDo (method, url, data, headers, callback, context)
    -- DEFINE A TICKET HANDLER CALLBACK TO HANDLE THE OAUTH RESPONSE.
    local ticketHandler = function (errorMessage, responseCode, responseHeaders, data, context, url)
        -- PASS THE OAUTH RESPONSE TO THE CUSTOM CALLBACK.
        local callbackFunction = self [callback]
        local success, callbackReturnValue = pcall (callbackFunction, self, errorMessage, responseCode, responseHeaders, data, context, url)
    end

    -- EXECUTE THE URL REQUEST WITH THE TICKET HANDLER CALLBACK.
    urlDo (method, url, data, headers, ticketHandler, context)
end

--- Perform an OAuth HTTP GET request.
--- @param url URL to send the request to.
--- @param headers HTTP headers to be sent with the request.
--- @param callback Callback function to be called with the response.
--- @param context Context to be passed to the callback function.
function oauth:urlGet (url, headers, callback, context)
    self:urlDo ('GET', url, data, headers, callback, context)
end

--- Perform an OAuth HTTP POST request.
--- @param url URL to send the request to.
--- @param data Data to be sent with the request.
--- @param headers HTTP headers to be sent with the request.
--- @param callback Callback function to be called with the response.
--- @param context Context to be passed to the callback function.
function oauth:urlPost (url, data, headers, callback, context)
    self:urlDo ('POST', url, data, headers, callback, context)
end

--- Perform an OAuth HTTP PUT request.
--- @param url URL to send the request to.
--- @param data Data to be sent with the request.
--- @param headers HTTP headers to be sent with the request.
--- @param callback Callback function to be called with the response.
--- @param context Context to be passed to the callback function.
function oauth:urlPut (url, data, headers, callback, context)
    self:urlDo ('PUT', url, data, headers, callback, context)
end

--- Perform an OAuth HTTP DELETE request.
--- @param url URL to send the request to.
--- @param headers HTTP headers to be sent with the request.
--- @param callback Callback function to be called with the response.
--- @param context Context to be passed to the callback function.
function oauth:urlDelete (url, headers, callback, context)
    self:urlDo ('DELETE', url, data, headers, callback, context)
end

--- Performs OAuth requests for custom HTTP methods.
--- @param url URL to send the request to.
--- @param method HTTP method to use (e.g. "GET", "POST", etc.).
--- @param data Data to be sent with the request.
--- @param headers HTTP headers to be sent with the request.
--- @param callback Callback function to be called with the response.
--- @param context Context to be passed to the callback function.
function oauth:urlCustom (url, method, data, headers, callback, context)
    self:urlDo (method, url, data, headers, callback, context)
end

return oauth
