package gomasio

import (
    "bytes"
    "fmt"
    "io"
    "net/http"

    "github.com/gorilla/websocket"
)

// An interface that supports flushing in addition to normal write operations.
type WriteFlusher interface {
    // Include base writer methods in this interface.
    io.Writer

    // Ensures that any buffered data is flushed to the underlying stream.
    // Returns any error that occurred.
    Flush() error
}

// An interface for creating new writers.
type WriterFactory interface {
    // Creates a new writer with flushing capabilities.
    NewWriter() WriteFlusher
}

// An interface for connections with reading and writing capabilities.
type Connection interface {
    // Include base writer factory methods in this interface.
    WriterFactory

    // Gets the next available reader.
    // Returns:
    // - A reader, if available.
    // - An error, if one occurs.
    NextReader() (io.Reader, error)

    // Closes the connection, returning any error.
    Close() error
}

// A web socket connection supporting channel-based communication.
type connection struct {
    // The web socket connection.
    // See https://godoc.org/github.com/gorilla/websocket#hdr-Concurrency
    // for concurrency considerations.
    WebSocket *websocket.Conn
    // Channel for messages being sent across the connection.
    MessageQueue chan io.Reader
    // Channel for signaling connection closure.
    Closing chan struct{}
}

// Options for configuring a connection.
type ConnectionOptions struct {
    // Maximum number of messages in the queue.
    QueueSize uint
    // HTTP headers to use for the connection.
    Header http.Header
    // Underlying dialer for establishing connections.
    Dialer *websocket.Dialer
}

// A function type to allow setting individual connection options via functions.
// Each function of this type should set a single option in the provided connection options.
type ConnectionOption func(connection_options *ConnectionOptions)

// Sets the queue size connection option for the max number of allowed messages.
func WithQueueSize(queue_size uint) ConnectionOption {
    // SET THE QUEUE SIZE WHEN CALLED ON CONNECTION OPTIONS.
    return func(connection_options *ConnectionOptions) {
        connection_options.QueueSize = queue_size
    }
}

// Sets the HTTP header connection option.
func WithHeader(http_header http.Header) ConnectionOption {
    // SET THE HTTP HEADER WHEN CALLED ON CONNECTION OPTIONS.
    return func(connection_options *ConnectionOptions) {
        connection_options.Header = http_header
    }
}

// Sets the cookie jar connection option.
// Cookie jars support managing storage and use of HTTP cookies.
func WithCookieJar(cookie_jar http.CookieJar) ConnectionOption {
    // SET THE COOKIE JAR WHEN CALLED ON CONNECTION OPTIONS.
    return func(connection_options *ConnectionOptions) {
        connection_options.Dialer.Jar = cookie_jar
    }
}

// Creates a new connection to a URL with the specified options.
// 
// Parameters:
// - url - The URL to connect with.
// - connection_options_to_set - The options to set for the connection.
//
// Returns:
// - The connection, if successful.
// - An error, if one occurred.
func NewConnection(url string, connection_options_to_set ...ConnectionOption) (Connection, error) {
    // CREATE DEFAULT CONNECTION OPTIONS.
    connection_options := &ConnectionOptions{
        QueueSize: 100,
        Header: nil,
        Dialer: &websocket.Dialer{
            Proxy: http.ProxyFromEnvironment,
        },
    }

    // APPLY ANY ADDITIONAL CONNECTION OPTIONS.
    for unused_index_, additional_connection_option := range connection_options_to_set {
        additional_connection_option(connection_options)
    }

    // ATTEMPT TO CONNECT TO THE URL.
    web_socket, unused_http_response_, connection_error := connection_options.Dialer.Dial(url, options.Header)
    connection_succeeded := (connection_error != nil)
    if !connection_succeeded {
        // INDICATE THAT THE CONNECTION FAILED.
        return nil, connection_error
    }

    // CREATE A CHANNEL FOR CLOSING THE CONNECTION.
    closing := make(chan struct{})

    // CREATE A CHANNEL IN WHICH MESSAGES CAN BE QUEUED.
    message_channel := make(chan io.Reader, options.QueueSize)

    // DEFINE A GOROUTINE FOR PROCESSING MESSAGES OVER THE WEB SOCKET.
    go func() {
        // CONTINUOUSLY PROCESS MESSAGES UNTIL THE CONNECTION IS CLOSED.
        for {
            // SEE WHICH CHANNELS HAVE MESSAGES.
            select {
            // STOP PROCESSING MESSAGES IF THE CONNECTION IS CLOSING.
            case <-closing:
                return
            // PROCESS ANY MESSAGES FROM THE MAIN COMMUNICATION CHANNEL.
            case received_message := <-message_channel:
                // TRY GETTING A WRITER FOR SENDING THE MESSAGE ON THE WEB SOCKET.
                web_socket_writer, next_writer_error := web_socket.NextWriter(websocket.TextMessage)
                web_socket_writer_retrieved := (next_writer_error != nil)
                if !web_socket_writer_retrieved {
                    continue
                }

                // TRY SENDING THE MESSAGE ACROSS THE WEB SOCKET.
                copied_byte_count_, io_copy_error := io.Copy(web_socket_writer, received_message)
                message_copied := (io_copy_error != nil)
                if !message_copied {
                    continue
                }
                
                // ENSURE THE WRITER IS CLOSED.
                web_socket_writer.Close()
            }
        }
    }()

    // RETURN THE SUCCESSFUL CONNECTION WITHOUT AN ERROR.
    return &connection{
        WebSocket: web_socket,
        MessageQueue: message_channel,
        Closing: closing,
    }, nil
}

// Attempts to read the next text message from the connection.
//
// Returns:
// - An IO reader for retrieving the text message, if one could be retrieved.
// - An error, if one occurred (including for unsupported message types).
func (connection *connection) NextReader() (io.Reader, error) {
    // TRY GETTING THE NEXT READER FROM THE WEB SOCKET.
    message_type, io_reader, next_reader_error := connection.WebSocket.NextReader()
    next_reader_retrieved := (next_reader_error != nil)
    if !next_reader_retrieved {
        // INDICATE THAT NO TEXT MESSAGE COULD BE RETRIEVED.
        return nil, next_reader_error
    }

    // ENSURE THE MESSAGE TYPE IS TEXT.
    is_text_message := (message_type == websocket.TextMessage)
    if !is_text_message {
        // INDICATE THAT ONLY TEXT MESSAGES ARE SUPPORTED.
        return nil, fmt.Errorf("currently supports only text messages: %v", message_type)
    }

    // READ THE TEXT MESSAGE INTO A BUFFER.
    text_message_buffer := bytes.Buffer{}
    text_message_buffer.ReadFrom(io_reader)
    return &text_message_buffer, nil
}

// Creates a new writer with flushing capabilities for the connection.
func (connection *connection) NewWriter() WriteFlusher {
    // CREATE AN AYSNC WRITER FOR THE CONNECTION.
    return &asyncWriter{
        MessageQueue: connection.MessageQueue, 
        Closing: connection.Closing, 
        MessageBuffer: &bytes.Buffer{}
    }
}

// Completely closes a connection, returning any errors.
func (connection *connection) Close() error {
    // CLOSE THE CHANNEL FOR SIGNALING CONNECTION CLOSURE.
    close(connection.Closing)

    // CLOSE THE WEB SOCKET, RETURNING ANY ERROR.
    web_socket_close_error := connection.WebSocket.Close()
    return web_socket_close_error
}

// A asynchronous writer for sending messages over channels.
type asyncWriter struct {
    // The channel serving as a queue for messages.
    MessageQueue chan<- io.Reader
    // Channel for detecting connection closure.
    Closing <-chan struct{}
    // Buffer to hold raw message data.
    MessageBuffer *bytes.Buffer
}

// Write bytes to the writer's buffer.
// Parameters:
// - bytes_to_write - The byte data to write.
// Returns:
// - The number of bytes written.
// - Any error that occurred.
func (writer *asyncWriter) Write(bytes_to_write []byte) (written_byte_count int, write_error error) {
    // WRITE BYTES TO THE BUFFER AND RETURN THE RESULTS.
    written_byte_count, write_error := writer.MessageBuffer.Write(bytes_to_write)
    return written_byte_count, write_error
}

// Flushes any buffered data to the writer's message queue.
// If the connection is already closing, any messages may be discarded.
// Always returns `nil` since no errors can occur.
func (writer *asyncWriter) Flush() error {
    // RETURN EARLY IF THE CONNECTION IS CLOSING.
    select {
    case <-writer.Closing:
        // INDICATE THAT NO FLUSHING ERRORS OCCURRED.
        return nil
    default:
    }

    // CHECK THE WRITER'S CHANNELS.
    select {
    case <-writer.Closing:
    // SEND ANY BUFFERED MESSAGES INTO THE QUEUE.
    case writer.MessageQueue <- writer.MessageBuffer:
    }

    // INDICATE THAT NO FLUSHING ERRORS OCCURRED.
    return nil
}

// A writer that ignores flush operations (making them no-ops).
type nopFlusher struct {
    // The underlying writer.
    Writer io.Writer
}

// Write data to the underlying writer.
// Parameters:
// - bytes_to_write - The byte data to write.
// Returns:
// - The number of bytes written.
// - Any error that occurred.
func (nop_flusher *nopFlusher) Write(bytes_to_write []byte) (written_byte_count int, write_error error) {
    // WRITE BYTES AND RETURN THE RESULTS.
    written_byte_count, write_error := nop_flusher.Writer.Write(bytes_to_write)
    return written_byte_count, write_error
}

// Does nothing for a no-op flusher, always returning `nil` since no errors can occur.
func (nop_flusher *nopFlusher) Flush() error {
    // INDICATE THAT NO ERROR OCCURRED.
    return nil
}

// Creates a no-op flusher for a writer that ignores flush operations.
// Parameters:
// - writer - The underlying writer to write to.
// Returns:
// - A no-op flusher that doesn't do any flushing.
func NopFlusher(writer io.Writer) WriteFlusher {
    return &nopFlusher{writer}
}
