package job

import (
	"context"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
)

type CsqttMembersJob struct{}

func NewCsqttMembersJob() *CsqttMembersJob { return new(CsqttMembersJob) }

func (j *CsqttMembersJob) Run() {
	if err := service.GetCsqttMemberService().SyncAll(context.Background()); err != nil {
		logger.Warning("csqtt members job:", err)
	}
	// Тот же 30-секундный цикл: пароли, срок и трафик клиентов qWDTT (perClient).
	if err := service.GetQwdttMemberService().SyncAll(context.Background()); err != nil {
		logger.Warning("qwdtt members job:", err)
	}
}
