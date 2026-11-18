package service

import (
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

// Регрессия: счётчики участника должны сохраняться после каждой синхронизации,
// иначе каждый проход заново засчитывает весь трафик с запуска CSQTT.
func TestCsqttSaveMemberAdvancesCounters(t *testing.T) {
	setupBulkDB(t)
	s := &CsqttMemberService{}
	server := csqttMemberServerClient{Password: "p1", Link: "csqtt://a", Up: 100, Down: 1000}

	if err := s.saveMember(2, "dad", model.CsqttMember{}, server); err != nil {
		t.Fatalf("create: %v", err)
	}
	member, ok := s.managedMember(2, "dad")
	if !ok || member.UpBytes != 100 || member.DownBytes != 1000 {
		t.Fatalf("after create: %+v", member)
	}

	server.Up, server.Down = 150, 5000
	if err := s.saveMember(2, "dad", member, server); err != nil {
		t.Fatalf("update: %v", err)
	}
	member, _ = s.managedMember(2, "dad")
	if member.UpBytes != 150 || member.DownBytes != 5000 {
		t.Fatalf("counters not advanced: %+v", member)
	}

	// Перезапуск CSQTT: счётчики с нуля тоже должны записаться.
	server.Up, server.Down = 0, 0
	if err := s.saveMember(2, "dad", member, server); err != nil {
		t.Fatalf("reset: %v", err)
	}
	member, _ = s.managedMember(2, "dad")
	if member.UpBytes != 0 || member.DownBytes != 0 {
		t.Fatalf("zero counters not stored: %+v", member)
	}
}
