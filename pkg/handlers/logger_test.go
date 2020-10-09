package handlers

import (
	"net/http"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type TestHook struct {
	Fired bool
	Entry *logrus.Entry
}

func (hook *TestHook) Fire(entry *logrus.Entry) error {
	hook.Fired = true
	hook.Entry = entry
	return nil
}

func (hook *TestHook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.DebugLevel,
		logrus.InfoLevel,
		logrus.WarnLevel,
		logrus.ErrorLevel,
		logrus.FatalLevel,
		logrus.PanicLevel,
	}
}

func TestNewLogEntry(t *testing.T) {
	hook := new(TestHook)
	logger := logrus.New()
	logger.Level = logrus.DebugLevel
	logger.AddHook(hook)
	logger.Formatter = &logrus.JSONFormatter{DisableTimestamp: true}
	l := &StructuredLogger{logger}

	mwle := l.NewLogEntry(&http.Request{})
	if mwle == nil {
		t.Error("Log entry is nil.")
	}
	assert.Equal(t, hook.Fired, true)
}

func TestWrite(t *testing.T) {
	hook := new(TestHook)
	logger := logrus.New()
	logger.Level = logrus.DebugLevel
	logger.AddHook(hook)
	logger.Formatter = &logrus.JSONFormatter{DisableTimestamp: true}

	entry := &StructuredLoggerEntry{Logger: logrus.NewEntry(logger)}

	entry.Write(200, 0, 2*time.Second)
	s, _ := hook.Entry.String()
	assert.Equal(t, s, "{\"level\":\"info\",\"msg\":\"request complete\",\"resp_bytes_length\":0,\"resp_elapsed_ms\":2000,\"resp_status\":200}\n")
	assert.Equal(t, hook.Fired, true)
}

func TestPanic(t *testing.T) {
	hook := new(TestHook)
	logger := logrus.New()
	logger.Level = logrus.DebugLevel
	logger.AddHook(hook)
	logger.Formatter = &logrus.JSONFormatter{DisableTimestamp: true}

	entry := &StructuredLoggerEntry{Logger: logrus.NewEntry(logger)}

	stack := []byte{1, 2}
	entry.Panic("We have a problem", stack)
	assert.Equal(t, hook.Fired, false)
}
