// Package net provides a net.Conn implementation for UDP packets.
package net

import (
	"bytes"
	"io"
	"math"
	"net"
)

// UDPConnOptions are options for UDPConn.
type UDPConnOptions struct {
	bufferedWrite bool
}

// WithUDPConnBufferedWrite change the behaviour of UDPConn to buffer or not all
// write calls until Flush is called. By default it will buffer all write calls.
func WithUDPConnBufferedWrite(buffered bool) func(*UDPConnOptions) {
	return func(o *UDPConnOptions) {
		o.bufferedWrite = buffered
	}
}

// UDPConn is a net.Conn implementation for UDP packets. It will buffer all
// write calls and write them to the connection when Flush is called.
type UDPConn struct {
	net.PacketConn

	connRead      bool
	addr          net.Addr
	readBuffer    *bytes.Buffer
	writeBuffer   *bytes.Buffer
	writeBuffered bool
}

// NewUDPConn creates a new UDPConn.
func NewUDPConn(conn net.PacketConn, optFuncs ...func(*UDPConnOptions)) *UDPConn {
	options := UDPConnOptions{
		bufferedWrite: true,
	}
	for _, optFunc := range optFuncs {
		optFunc(&options)
	}
	return &UDPConn{
		PacketConn:    conn,
		writeBuffer:   new(bytes.Buffer),
		writeBuffered: options.bufferedWrite,
	}
}

// Read reads data from the connection.
func (c *UDPConn) Read(p []byte) (int, error) {
	if !c.connRead {
		if n, err := c.Receive(); err != nil {
			return n, err
		}
	}
	return c.readBuffer.Read(p)
}

// Write writes data to an internal buffer.
func (c *UDPConn) Write(p []byte) (int, error) {
	if c.writeBuffered {
		return c.writeBuffer.Write(p)
	}
	defer func() {
		c.connRead = false
	}()
	// always use Write for pre-connected connection
	if conn, ok := c.PacketConn.(net.Conn); ok {
		return conn.Write(p)
	}
	return c.WriteTo(p, c.addr)
}

// Receive reads data from the connection.
func (c *UDPConn) Receive() (int, error) {
	buffer := make([]byte, int64(math.Pow(2, 16))) // maximum UDP packet size
	n, addr, err := c.ReadFrom(buffer)
	if err != nil {
		return n, err
	}
	c.addr = addr
	c.readBuffer = bytes.NewBuffer(buffer[:n])
	c.connRead = true
	return n, nil
}

// Close writes the internal buffer to the connection.
func (c *UDPConn) Close() error {
	if c.writeBuffer.Len() == 0 {
		return nil
	}
	defer func() {
		c.connRead = false
	}()
	n, err := c.WriteTo(c.writeBuffer.Bytes(), c.addr)
	if err != nil {
		return err
	}
	if n != c.writeBuffer.Len() {
		return io.ErrShortWrite
	}
	c.writeBuffer.Reset()
	return nil
}

// RemoteAddr returns the remote network address, if known.
func (c *UDPConn) RemoteAddr() net.Addr {
	return c.addr
}
