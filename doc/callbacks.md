# Callbacks Reference

The callback system allows you to hook into every stage of the SMTP transaction. All callbacks are optional—if not set, the server uses sensible defaults.

## Callback Structure

```go
type Callbacks struct {
    OnConnect        func(ctx context.Context, conn *Connection) error
    OnDisconnect     func(ctx context.Context, conn *Connection)
    OnHelo           func(ctx context.Context, conn *Connection, hostname string) error
    OnEhlo           func(ctx context.Context, conn *Connection, hostname string) (extensions map[Extension]string, err error)
    OnStartTLS       func(ctx context.Context, conn *Connection) error
    OnAuth           func(ctx context.Context, conn *Connection, mechanism, identity, password string) error
    OnMailFrom       func(ctx context.Context, conn *Connection, from Path, params map[string]string) error
    OnRcptTo         func(ctx context.Context, conn *Connection, to Path, params map[string]string) error
    OnData           func(ctx context.Context, conn *Connection) error
    OnBDAT           func(ctx context.Context, conn *Connection, size int64, last bool) error
    OnMessage        func(ctx context.Context, conn *Connection, mail *Mail) error
    OnReset          func(ctx context.Context, conn *Connection)
    OnVerify         func(ctx context.Context, conn *Connection, address string) (MailboxAddress, error)
    OnExpand         func(ctx context.Context, conn *Connection, listName string) ([]MailboxAddress, error)
    OnUnknownCommand func(ctx context.Context, conn *Connection, command, args string) *Response
}
```

## Connection Lifecycle Callbacks

### OnConnect

Called when a new client connects, before the greeting is sent.

```go
OnConnect func(ctx context.Context, conn *Connection) error
```

**Purpose**: Connection-level validation, rate limiting, IP blacklisting.

**Return**:
- `nil`: Accept the connection
- `error`: Reject with `554 Connection rejected`

**Example: IP Blacklist**
```go
OnConnect: func(ctx context.Context, conn *raven.Connection) error {
    ip := extractIP(conn.RemoteAddr())
    
    if isBlacklisted(ip) {
        log.Printf("Rejected blacklisted IP: %s", ip)
        return fmt.Errorf("connection not allowed")
    }
    
    // Rate limiting
    if !rateLimiter.Allow(ip) {
        return fmt.Errorf("too many connections")
    }
    
    return nil
},
```

**Example: Connection Logging**
```go
OnConnect: func(ctx context.Context, conn *raven.Connection) error {
    log.Printf("[%s] New connection from %s",
        conn.Trace.ID,
        conn.RemoteAddr())
    return nil
},
```

### OnDisconnect

Called when a client disconnects (for any reason).

```go
OnDisconnect func(ctx context.Context, conn *Connection)
```

**Purpose**: Cleanup, logging, metrics collection.

**Note**: No return value—connection is already closing.

**Example: Session Logging**
```go
OnDisconnect: func(ctx context.Context, conn *raven.Connection) {
    duration := time.Since(conn.Trace.ConnectedAt)
    log.Printf("[%s] Disconnected after %v, %d commands, %d messages",
        conn.Trace.ID,
        duration,
        conn.Trace.CommandCount,
        conn.Trace.TransactionCount)
    
    // Report metrics
    metrics.ConnectionDuration.Observe(duration.Seconds())
    metrics.MessagesReceived.Add(float64(conn.Trace.TransactionCount))
},
```

## SMTP Handshake Callbacks

### OnHelo

Called when HELO command is received.

```go
OnHelo func(ctx context.Context, conn *Connection, hostname string) error
```

**Purpose**: Validate client hostname, logging.

**Return**:
- `nil`: Accept HELO
- `error`: Reject with `550` response

**Example**
```go
OnHelo: func(ctx context.Context, conn *raven.Connection, hostname string) error {
    log.Printf("[%s] HELO from %s", conn.Trace.ID, hostname)
    
    // Optionally verify hostname
    if hostname == "" || hostname == "localhost" {
        // Allow but log
        log.Printf("[%s] Warning: generic hostname", conn.Trace.ID)
    }
    
    return nil
},
```

### OnEhlo

Called when EHLO command is received. Can modify the advertised extensions.

```go
OnEhlo func(ctx context.Context, conn *Connection, hostname string) (extensions map[Extension]string, err error)
```

**Purpose**: Customize extensions per connection, validate client.

**Return**:
- `nil, nil`: Use default extensions
- `extensions, nil`: Override extensions list
- `_, error`: Reject with `550` response

**Example: Conditional Extensions**
```go
OnEhlo: func(ctx context.Context, conn *raven.Connection, hostname string) (map[raven.Extension]string, error) {
    // Don't offer AUTH until TLS is established
    if !conn.IsTLS() {
        // Return nil to use defaults, AUTH will still be offered
        // To customize, build the map manually
        return nil, nil
    }
    
    // Log the greeting
    log.Printf("[%s] EHLO from %s", conn.Trace.ID, hostname)
    
    return nil, nil
},
```

**Example: Custom Extensions**
```go
OnEhlo: func(ctx context.Context, conn *raven.Connection, hostname string) (map[raven.Extension]string, error) {
    // Build custom extension set
    extensions := map[raven.Extension]string{
        raven.Ext8BitMIME:           "",
        raven.ExtPipelining:         "",
        raven.ExtEnhancedStatusCodes: "",
    }
    
    // Only offer SIZE if we have storage available
    if hasStorageAvailable() {
        extensions[raven.ExtSize] = "52428800"  // 50 MB
    }
    
    // Only offer AUTH over TLS
    if conn.IsTLS() {
        extensions[raven.ExtAuth] = "PLAIN LOGIN"
    } else {
        extensions[raven.ExtSTARTTLS] = ""
    }
    
    return extensions, nil
},
```

### OnStartTLS

Called before TLS handshake begins.

```go
OnStartTLS func(ctx context.Context, conn *Connection) error
```

**Purpose**: Logging, conditional TLS acceptance.

**Return**:
- `nil`: Proceed with TLS handshake
- `error`: Reject STARTTLS command

**Example**
```go
OnStartTLS: func(ctx context.Context, conn *raven.Connection) error {
    log.Printf("[%s] Starting TLS upgrade", conn.Trace.ID)
    return nil
},
```

### OnAuth

Called when authentication is attempted. You must verify the credentials.

```go
OnAuth func(ctx context.Context, conn *Connection, mechanism, identity, password string) error
```

**Parameters**:
- `mechanism`: The SASL mechanism used (`"PLAIN"` or `"LOGIN"`)
- `identity`: The username/email provided
- `password`: The password provided

**Return**:
- `nil`: Authentication successful
- `error`: Authentication failed with `554 5.7.8`

**Example: Database Authentication**
```go
OnAuth: func(ctx context.Context, conn *raven.Connection, mechanism, identity, password string) error {
    log.Printf("[%s] Auth attempt: %s using %s", conn.Trace.ID, identity, mechanism)
    
    // Look up user in database
    user, err := db.GetUserByEmail(ctx, identity)
    if err != nil {
        return fmt.Errorf("authentication failed")
    }
    
    // Verify password (use proper hashing!)
    if !verifyPassword(password, user.PasswordHash) {
        // Log failed attempt
        auditLog.AuthFailure(identity, conn.RemoteAddr())
        return fmt.Errorf("authentication failed")
    }
    
    // Log success
    auditLog.AuthSuccess(identity, conn.RemoteAddr())
    
    return nil
},
```

**Example: LDAP Authentication**
```go
OnAuth: func(ctx context.Context, conn *raven.Connection, mechanism, identity, password string) error {
    ldapConn, err := ldap.Dial("tcp", "ldap.example.com:389")
    if err != nil {
        log.Printf("LDAP connection failed: %v", err)
        return fmt.Errorf("authentication service unavailable")
    }
    defer ldapConn.Close()
    
    // Bind with user credentials
    userDN := fmt.Sprintf("uid=%s,ou=users,dc=example,dc=com", identity)
    err = ldapConn.Bind(userDN, password)
    if err != nil {
        return fmt.Errorf("authentication failed")
    }
    
    return nil
},
```

## Mail Transaction Callbacks

### OnMailFrom

Called when MAIL FROM command is received.

```go
OnMailFrom func(ctx context.Context, conn *Connection, from Path, params map[string]string) error
```

**Parameters**:
- `from`: The sender's address (may be null path for bounces)
- `params`: MAIL FROM parameters (`SIZE`, `BODY`, `SMTPUTF8`, etc.)

**Return**:
- `nil`: Accept sender
- `error`: Reject with `550` response

**Example: Sender Validation**
```go
OnMailFrom: func(ctx context.Context, conn *raven.Connection, from raven.Path, params map[string]string) error {
    // Allow null sender for bounces
    if from.IsNull() {
        return nil
    }
    
    // For authenticated users, verify they own the address
    if conn.IsAuthenticated() {
        authUser := conn.Auth.Identity
        senderDomain := from.Mailbox.Domain
        
        if !userCanSendFrom(authUser, from.Mailbox.String()) {
            return fmt.Errorf("not authorized to send from this address")
        }
    }
    
    // Check sender reputation
    if isKnownSpammer(from.Mailbox.String()) {
        return fmt.Errorf("sender rejected")
    }
    
    return nil
},
```

**Example: Size Check**
```go
OnMailFrom: func(ctx context.Context, conn *raven.Connection, from raven.Path, params map[string]string) error {
    if sizeStr, ok := params["SIZE"]; ok {
        size, _ := strconv.ParseInt(sizeStr, 10, 64)
        
        // Custom per-user limits
        if conn.IsAuthenticated() {
            userLimit := getUserSizeLimit(conn.Auth.Identity)
            if size > userLimit {
                return fmt.Errorf("message too large for your account")
            }
        }
    }
    
    return nil
},
```

### OnRcptTo

Called for each RCPT TO command.

```go
OnRcptTo func(ctx context.Context, conn *Connection, to Path, params map[string]string) error
```

**Parameters**:
- `to`: The recipient's address
- `params`: RCPT TO parameters (`NOTIFY`, `ORCPT` for DSN)

**Return**:
- `nil`: Accept recipient
- `error`: Reject with `550` response

**Example: Local Delivery Only**
```go
OnRcptTo: func(ctx context.Context, conn *raven.Connection, to raven.Path, params map[string]string) error {
    domain := to.Mailbox.Domain
    
    // Only accept mail for our domains
    if !isLocalDomain(domain) {
        // Unless user is authenticated (can relay)
        if !conn.IsAuthenticated() {
            return fmt.Errorf("relay access denied")
        }
    }
    
    // Check if mailbox exists
    if isLocalDomain(domain) && !mailboxExists(to.Mailbox.String()) {
        return fmt.Errorf("user unknown")
    }
    
    return nil
},
```

**Example: Per-Recipient Processing**
```go
OnRcptTo: func(ctx context.Context, conn *raven.Connection, to raven.Path, params map[string]string) error {
    // Check vacation/auto-responder
    if isOnVacation(to.Mailbox.String()) {
        // Still accept, but flag for auto-response
        // (Store in connection context or similar)
    }
    
    // Check forwarding
    if forward := getForwarding(to.Mailbox.String()); forward != "" {
        // Handle forwarding logic
    }
    
    return nil
},
```

### OnData

Called when DATA command is received, before reading message content.

```go
OnData func(ctx context.Context, conn *Connection) error
```

**Purpose**: Pre-message validation, resource allocation.

**Return**:
- `nil`: Ready to receive data
- `error`: Reject with `554` response

**Example**
```go
OnData: func(ctx context.Context, conn *raven.Connection) error {
    // Ensure we have storage available
    if !hasStorageSpace() {
        return fmt.Errorf("insufficient storage")
    }
    
    // Rate limiting on messages
    if !messageRateLimiter.Allow(conn.Auth.Identity) {
        return fmt.Errorf("message rate limit exceeded")
    }
    
    return nil
},
```

### OnBDAT

Called when BDAT command is received (CHUNKING extension, RFC 3030).

```go
OnBDAT func(ctx context.Context, conn *Connection, size int64, last bool) error
```

**Parameters**:
- `size`: The size of the incoming chunk in bytes
- `last`: `true` if this is the final chunk (BDAT LAST)

**Return**:
- `nil`: Ready to receive chunk data
- `error`: Reject chunk, discard data, and reset transaction

**Note**: This callback is only invoked when `EnableChunking` is `true` in the server configuration.

**Example: Chunk Logging**
```go
OnBDAT: func(ctx context.Context, conn *raven.Connection, size int64, last bool) error {
    log.Printf("[%s] BDAT chunk: %d bytes, last=%v", 
        conn.Trace.ID, size, last)
    return nil
},
```

**Example: Streaming Validation**
```go
OnBDAT: func(ctx context.Context, conn *raven.Connection, size int64, last bool) error {
    // Check cumulative size
    mail := conn.CurrentMail()
    currentSize := int64(len(mail.Raw))
    
    // Apply per-user limits
    if conn.IsAuthenticated() {
        userLimit := getUserSizeLimit(conn.Auth.Identity)
        if currentSize+size > userLimit {
            return fmt.Errorf("message exceeds your size limit")
        }
    }
    
    // Resource check before each chunk
    if !hasStorageSpace() {
        return fmt.Errorf("insufficient storage")
    }
    
    return nil
},
```

**BDAT vs DATA**: Both methods result in the same `OnMessage` callback being invoked when the message is complete. The `OnBDAT` callback provides additional control for chunk-by-chunk validation.

### OnMessage

Called when a complete message has been received. This is the main message processing callback.

```go
OnMessage func(ctx context.Context, conn *Connection, mail *Mail) error
```

**Parameters**:
- `mail`: Complete mail object with envelope and content

**Return**:
- `nil`: Message accepted (returns `250 OK`)
- `error`: Message rejected with `554` response

**Example: Store and Forward**
```go
OnMessage: func(ctx context.Context, conn *raven.Connection, mail *raven.Mail) error {
    // Log receipt
    log.Printf("[%s] Message %s from %s to %d recipients",
        conn.Trace.ID,
        mail.ID,
        mail.Envelope.From.String(),
        len(mail.Envelope.To))
    
    // Store message
    err := messageStore.Save(ctx, mail)
    if err != nil {
        log.Printf("Failed to store message: %v", err)
        return fmt.Errorf("temporary failure, please retry")
    }
    
    // Queue for delivery
    for _, rcpt := range mail.Envelope.To {
        err := deliveryQueue.Enqueue(ctx, mail.ID, rcpt.Address.Mailbox.String())
        if err != nil {
            log.Printf("Failed to queue delivery: %v", err)
        }
    }
    
    return nil
},
```

**Example: Spam Filtering**
```go
OnMessage: func(ctx context.Context, conn *raven.Connection, mail *raven.Mail) error {
    // Run spam check
    score, err := spamFilter.Check(mail.Raw)
    if err != nil {
        log.Printf("Spam check failed: %v", err)
        // Accept anyway on error
    } else if score > spamThreshold {
        log.Printf("Message rejected as spam (score: %.2f)", score)
        return fmt.Errorf("message rejected as spam")
    }
    
    // Add spam header
    if score > 0 {
        mail.AddHeader("X-Spam-Score", fmt.Sprintf("%.2f", score))
    }
    
    return storeMessage(ctx, mail)
},
```

**Example: Content Inspection**
```go
OnMessage: func(ctx context.Context, conn *raven.Connection, mail *raven.Mail) error {
    // Check for prohibited content
    subject := mail.Content.Headers.Get("Subject")
    
    // Virus scan
    if containsVirus(mail.Raw) {
        return fmt.Errorf("message contains virus")
    }
    
    // Check attachment types
    contentType := mail.Content.Headers.Get("Content-Type")
    if strings.Contains(contentType, "application/x-msdownload") {
        return fmt.Errorf("executable attachments not allowed")
    }
    
    return deliverMessage(ctx, mail)
},
```

### OnReset

Called when RSET command is received.

```go
OnReset func(ctx context.Context, conn *Connection)
```

**Purpose**: Cleanup any per-transaction state.

**Note**: No return value.

**Example**
```go
OnReset: func(ctx context.Context, conn *raven.Connection) {
    log.Printf("[%s] Transaction reset", conn.Trace.ID)
    // Clean up any temporary files, etc.
},
```

## Address Verification Callbacks

### OnVerify

Called when VRFY command is received.

```go
OnVerify func(ctx context.Context, conn *Connection, address string) (MailboxAddress, error)
```

**Return**:
- `address, nil`: Return verified address
- `_, error`: Address not found (returns `550`)

**Note**: Many servers disable VRFY for privacy/security.

**Example**
```go
OnVerify: func(ctx context.Context, conn *raven.Connection, address string) (raven.MailboxAddress, error) {
    // Only allow for authenticated users
    if !conn.IsAuthenticated() {
        return raven.MailboxAddress{}, fmt.Errorf("VRFY disabled")
    }
    
    user, err := lookupUser(address)
    if err != nil {
        return raven.MailboxAddress{}, fmt.Errorf("user not found")
    }
    
    return raven.MailboxAddress{
        LocalPart:   user.Username,
        Domain:      "example.com",
        DisplayName: user.FullName,
    }, nil
},
```

### OnExpand

Called when EXPN command is received.

```go
OnExpand func(ctx context.Context, conn *Connection, listName string) ([]MailboxAddress, error)
```

**Return**:
- `addresses, nil`: Return list members
- `_, error`: List not found (returns `550`)

**Note**: Usually disabled for privacy/security.

**Example**
```go
OnExpand: func(ctx context.Context, conn *raven.Connection, listName string) ([]raven.MailboxAddress, error) {
    // Disabled by default
    return nil, fmt.Errorf("EXPN disabled")
},
```

## Unknown Command Handler

### OnUnknownCommand

Called for unrecognized commands.

```go
OnUnknownCommand func(ctx context.Context, conn *Connection, command, args string) *Response
```

**Return**:
- `nil`: Use default `500 Command not recognized`
- `*Response`: Custom response

**Example: Custom Commands**
```go
OnUnknownCommand: func(ctx context.Context, conn *raven.Connection, command, args string) *raven.Response {
    switch command {
    case "HELP":
        return &raven.Response{
            Code:    214,
            Message: "See https://example.com/smtp-help for assistance",
        }
    case "XCLIENT":
        // Handle proxy protocol
        return handleXClient(conn, args)
    default:
        // Use default response
        return nil
    }
},
```

## Best Practices

### Error Handling

- Return descriptive but not overly detailed error messages
- Log detailed errors server-side
- Don't expose internal implementation details

```go
OnAuth: func(ctx context.Context, conn *raven.Connection, mechanism, identity, password string) error {
    err := authenticateUser(identity, password)
    if err != nil {
        // Log details internally
        log.Printf("[%s] Auth failed for %s: %v", conn.Trace.ID, identity, err)
        // Return generic message to client
        return fmt.Errorf("authentication failed")
    }
    return nil
},
```

### Context Usage

Use the provided context for cancellation and deadlines:

```go
OnMessage: func(ctx context.Context, conn *raven.Connection, mail *raven.Mail) error {
    // Respect context cancellation
    select {
    case <-ctx.Done():
        return ctx.Err()
    default:
    }
    
    // Pass context to downstream operations
    return db.SaveMessage(ctx, mail)
},
```

### Connection State

Access connection information for decisions:

```go
OnMailFrom: func(ctx context.Context, conn *raven.Connection, from raven.Path, params map[string]string) error {
    // Check TLS
    if conn.IsTLS() {
        // More permissive for secure connections
    }
    
    // Check authentication
    if conn.IsAuthenticated() {
        authUser := conn.Auth.Identity
        // Authenticated user logic
    }
    
    // Access trace info
    clientIP := conn.Trace.RemoteAddr.String()
    clientHostname := conn.Trace.ClientHostname
    
    return nil
},
```
