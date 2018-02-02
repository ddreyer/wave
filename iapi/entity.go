package iapi

import (
	"context"
	"crypto/rand"
	"time"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/crypto"
	"github.com/immesys/wave/serdes"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"vuvuzela.io/crypto/ibe"
)

type IAPIs struct {
}

type PNewEntity struct {
	Contact *string
	Comment *string
	//If not specified, defaults to Now
	ValidFrom *time.Time
	//If not specified defaults to Now+30 days
	ValidUntil *time.Time
}
type RNewEntity struct {
	PublicDER []byte
	SecretDER []byte
}

func (iapi *IAPIs) NewEntity(ctx context.Context, p *PNewEntity) (*RNewEntity, error) {
	en := serdes.WaveEntitySecret{}

	if p.Comment != nil {
		en.Entity.TBS.Comment = *p.Comment
	}
	if p.Contact != nil {
		en.Entity.TBS.Contact = *p.Contact
	}
	if p.ValidFrom != nil {
		en.Entity.TBS.Validity.NotBefore = *p.ValidFrom
	} else {
		en.Entity.TBS.Validity.NotBefore = time.Now()
	}
	if p.ValidUntil != nil {
		en.Entity.TBS.Validity.NotAfter = *p.ValidUntil
	} else {
		en.Entity.TBS.Validity.NotAfter = time.Now().Add(30 * 24 * time.Hour)
	}

	//add the WR1 keys
	kr := serdes.EntityKeyring{}

	//Ed25519
	publicEd25519, privateEd25519, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ke := serdes.EntityKeyringEntry{
		Public: serdes.EntityPublicKey{
			Capabilities: []int{int(CapAttestation), int(CapCertification)},
			Key:          asn1.NewExternal(serdes.EntityPublicEd25519(publicEd25519)),
		},
		Private: asn1.NewExternal(serdes.EntitySecretEd25519(privateEd25519)),
	}
	kr.Keys = append(kr.Keys, ke)

	//Curve25519
	{
		var secret [32]byte
		_, err = rand.Read(secret[:])
		if err != nil {
			return nil, err
		}
		var public [32]byte
		curve25519.ScalarBaseMult(&public, &secret)
		ke := serdes.EntityKeyringEntry{
			Public: serdes.EntityPublicKey{
				Capabilities: []int{int(CapEncryption)},
				Key:          asn1.NewExternal(serdes.EntityPublicCurve25519(public[:])),
			},
			Private: asn1.NewExternal(serdes.EntitySecretCurve25519(secret[:])),
		}
		kr.Keys = append(kr.Keys, ke)
	}
	//IBE
	{
		params, master := ibe.Setup(rand.Reader)
		paramsblob, err := params.MarshalBinary()
		if err != nil {
			return nil, err
		}
		masterblob, err := master.MarshalBinary()
		if err != nil {
			return nil, err
		}
		ke := serdes.EntityKeyringEntry{
			Public: serdes.EntityPublicKey{
				Capabilities: []int{int(CapEncryption)},
				Key:          asn1.NewExternal(serdes.EntityParamsIBE_BN256(paramsblob)),
			},
			Private: asn1.NewExternal(serdes.EntitySecretMasterIBE_BN256(masterblob)),
		}
		kr.Keys = append(kr.Keys, ke)
	}
	//OAQUE
	{
		params, master, err := crypto.GenerateOAQUEKeys()
		paramsblob := params.Marshal()
		if err != nil {
			return nil, err
		}
		masterblob := master.Marshal()
		if err != nil {
			return nil, err
		}
		ke := serdes.EntityKeyringEntry{
			Public: serdes.EntityPublicKey{
				Capabilities: []int{int(CapEncryption), int(CapAuthorization)},
				Key:          asn1.NewExternal(serdes.EntityParamsOQAUE_BN256_s20(paramsblob)),
			},
			Private: asn1.NewExternal(serdes.EntitySecretMasterOQAUE_BN256_s20(masterblob)),
		}
		kr.Keys = append(kr.Keys, ke)
	}
	//Put the keyring into the secret entity object
	en.Keyring = asn1.NewExternal(kr)

	//For all our secret keys, put the public ones in the public entity
	for _, ke := range kr.Keys[1:] {
		en.Entity.TBS.Keys = append(en.Entity.TBS.Keys, ke.Public)
	}
	//Put the canonical certification key in
	en.Entity.TBS.VerifyingKey = kr.Keys[0].Public

	//TODO commitmentrevocation

	//Serialize TBS and sign it
	der, err := asn1.Marshal(en.Entity.TBS)
	if err != nil {
		return nil, err
	}
	en.Entity.Signature = ed25519.Sign(privateEd25519, der)

	//Serialize wrapped public part
	publicEntity := serdes.WaveWireObject{}
	publicEntity.Content = asn1.NewExternal(en.Entity)
	publicDER, err := asn1.Marshal(publicEntity.Content)
	if err != nil {
		return nil, err
	}
	//Serialize secret
	secretEntity := serdes.WaveWireObject{}
	secretEntity.Content = asn1.NewExternal(en)
	secretDER, err := asn1.Marshal(secretEntity.Content)
	if err != nil {
		return nil, err
	}
	return &RNewEntity{
		PublicDER: publicDER,
		SecretDER: secretDER,
	}, nil
}
