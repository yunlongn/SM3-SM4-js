package com.xingri.biz.bizck.encrypt.smutil;


import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.xingri.xpro.common.exception.BussinessException;
import lombok.Data;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Data
public class SM4Utils
{
    private String secretKey = "";
    private String iv = "";
    private boolean hexString = false;

    public SM4Utils()
    {
    }

    public String encryptData_ECB(String plainText)
    {
        try
        {
            SM4_Context ctx = new SM4_Context();
            ctx.isPadding = true;
            ctx.mode = SM4.SM4_ENCRYPT;

            byte[] keyBytes;
            keyBytes = secretKey.getBytes();
            SM4 sm4 = new SM4();
            sm4.sm4_setkey_enc(ctx, keyBytes);
            byte[] encrypted = sm4.sm4_crypt_ecb(ctx, plainText.getBytes("UTF-8"));
            String cipherText = new BASE64Encoder().encode(encrypted);
//            System.out.println(Util.byteToHex(encrypted));
            if (cipherText != null && cipherText.trim().length() > 0)
            {
                Pattern p = Pattern.compile("\\s*|\t|\r|\n");
                Matcher m = p.matcher(cipherText);
                cipherText = m.replaceAll("");
            }
            return cipherText;
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return null;
        }
    }

    public String decryptData_ECB(String cipherText)
    {
        try
        {
            SM4_Context ctx = new SM4_Context();
            ctx.isPadding = true;
            ctx.mode = SM4.SM4_DECRYPT;

            byte[] keyBytes;
            keyBytes = secretKey.getBytes();
            SM4 sm4 = new SM4();
            sm4.sm4_setkey_dec(ctx, keyBytes);
            byte[] decrypted = sm4.sm4_crypt_ecb(ctx, new BASE64Decoder().decodeBuffer(cipherText));
            return new String(decrypted, "UTF-8");
        }
        catch (Exception e)
        {
//            e.printStackTrace();
            throw new BussinessException("参数解析异常");
//            return null;
        }
    }

    public String encryptData_CBC(String plainText){
        try{
            SM4_Context ctx = new SM4_Context();
            ctx.isPadding = true;
            ctx.mode = SM4.SM4_ENCRYPT;

            byte[] keyBytes;
            byte[] ivBytes;

            keyBytes = secretKey.getBytes();
            ivBytes = iv.getBytes();

            SM4 sm4 = new SM4();
            sm4.sm4_setkey_enc(ctx, keyBytes);
            byte[] encrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, plainText.getBytes("UTF-8"));
//            System.out.println(Util.byteToHex(encrypted));
            String cipherText = new BASE64Encoder().encode(encrypted);
            if (cipherText != null && cipherText.trim().length() > 0)
            {
                Pattern p = Pattern.compile("\\s*|\t|\r|\n");
                Matcher m = p.matcher(cipherText);
                cipherText = m.replaceAll("");
            }
            return cipherText;
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return null;
        }
    }

    public String decryptData_CBC(String cipherText)
    {
        try
        {
            SM4_Context ctx = new SM4_Context();
            ctx.isPadding = true;
            ctx.mode = SM4.SM4_DECRYPT;

            byte[] keyBytes;
            byte[] ivBytes;
            if (hexString)
            {
                keyBytes = Util.hexStringToBytes(secretKey);
                ivBytes = Util.hexStringToBytes(iv);
            }
            else
            {
                keyBytes = secretKey.getBytes();
                ivBytes = iv.getBytes();
            }

            SM4 sm4 = new SM4();
            sm4.sm4_setkey_dec(ctx, keyBytes);
            byte[] decrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, new BASE64Decoder().decodeBuffer(cipherText));
            return new String(decrypted, "UTF-8");
        }
        catch (Exception e)
        {
            throw new BussinessException("参数解析异常");
//            return null;
        }
    }

    public static String ckDecryptData(String cipherText) {
        SM4Utils sm4 = new SM4Utils();
        sm4.setSecretKey("11HDESaAhiHHugDz");
        String plainText = "";
        plainText = sm4.decryptData_ECB(cipherText);
//        System.out.println("明文: " + plainText);
        JSONObject plainTextJSONObject = JSON.parseObject(plainText);


        sm4.setIv(plainTextJSONObject.getString("vi"));
        plainText = sm4.decryptData_CBC(plainTextJSONObject.getString("data"));

//        System.out.println("最终明文: " + plainText);
        // 验证签名
        if (!plainTextJSONObject.getString("encrypt").equals(SM3.convert(plainText))) {
            throw new BussinessException("参数被篡改，请检查参数");
        }


        return plainText;
    }
    public static void encryptFlow() throws IOException
    {
        String plainText ="{\"ckSignRelationRequestList\":[{\"OPERATION_TELLER_NO\":\"000227\",\"KID_CARD_NO\":\"6231500005627705\",\"START_DATE\":\"20191017\",\"SIGN_STATUS\":\"A\",\"LAST_UPDATE_DATE\":\"20191017\",\"PTRCH_GLOBAL_TYPE\":\"0\",\"PTRCH_CLIENT_NO\":\"10002920274\",\"RESCIND_DATE\":\"\",\"PTRCH_GLOBAL_ID\":\"610111199109260092\",\"PTRCH_CLIENT_NAME\":\"哈阿是噶是\",\"RESCIND_TELLER_NO\":\"\",\"CERT_NO\":\"11\",\"KID_CLIENT_NO\":\"10002920276\",\"SIGN_ID\":\"8\",\"MATURE_DATE\":\"20260926\",\"KID_CLIENT_NAME\":\"鱼哈\",\"HSLDR_FLAG\":\"Y\",\"REMARK\":\"\"},{\"OPERATION_TELLER_NO\":\"000227\",\"KID_CARD_NO\":\"6231500005627739\",\"START_DATE\":\"20191017\",\"SIGN_STATUS\":\"A\",\"LAST_UPDATE_DATE\":\"20191017\",\"PTRCH_GLOBAL_TYPE\":\"0\",\"PTRCH_CLIENT_NO\":\"10002920274\",\"RESCIND_DATE\":\"\",\"PTRCH_GLOBAL_ID\":\"610111199109260092\",\"PTRCH_CLIENT_NAME\":\"哈阿是噶是\",\"RESCIND_TELLER_NO\":\"\",\"CERT_NO\":\"16\",\"KID_CLIENT_NO\":\"10002920280\",\"SIGN_ID\":\"12\",\"MATURE_DATE\":\"20260926\",\"KID_CLIENT_NAME\":\"好的很\",\"HSLDR_FLAG\":\"Y\",\"REMARK\":\"\"},{\"OPERATION_TELLER_NO\":\"000227\",\"KID_CARD_NO\":\"6231500005627732\",\"START_DATE\":\"20191017\",\"SIGN_STATUS\":\"A\",\"LAST_UPDATE_DATE\":\"20191017\",\"PTRCH_GLOBAL_TYPE\":\"0\",\"PTRCH_CLIENT_NO\":\"10002920274\",\"RESCIND_DATE\":\"\",\"PTRCH_GLOBAL_ID\":\"610111199109260092\",\"PTRCH_CLIENT_NAME\":\"哈阿是噶是\",\"RESCIND_TELLER_NO\":\"\",\"CERT_NO\":\"16\",\"KID_CLIENT_NO\":\"10002920233280\",\"SIGN_ID\":\"14\",\"MATURE_DATE\":\"20260926\",\"KID_CLIENT_NAME\":\"好的很\",\"HSLDR_FLAG\":\"Y\",\"REMARK\":\"\"}]}";
        SM4Utils sm4 = new SM4Utils();
        sm4.secretKey = "mLGFIwf7fnYckSqL";
        sm4.iv = "mLGFIwf7fnYckSqL";
        String cipherText = sm4.encryptData_CBC(plainText);
        System.out.println();
        System.out.println();
        System.out.println("CBC加密 这里随机用个vi:" + cipherText);
        JSONObject plainTextJSONObject = new JSONObject();
        plainTextJSONObject.put("encrypt", SM3.convert(plainText));
        plainTextJSONObject.put("data", cipherText);
        plainTextJSONObject.put("vi", sm4.iv);
        System.out.println();
        System.out.println();
        System.out.println("准备ECB加密" + plainTextJSONObject.toJSONString());
        System.out.println();
        System.out.println();
        String encryptData_ECBStr = sm4.encryptData_ECB(plainTextJSONObject.toJSONString());
        System.out.println("最终" + encryptData_ECBStr);
    }



    public static void main(String[] args) throws IOException
    {
        encryptFlow();
        System.out.println("解密！" + ckDecryptData("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"));
        String plainText ="{\"ckSignRelationRequestList\":[{\"OPERATION_TELLER_NO\":\"000227\",\"KID_CARD_NO\":\"6231500005627705\",\"START_DATE\":\"20191017\",\"SIGN_STATUS\":\"A\",\"LAST_UPDATE_DATE\":\"20191017\",\"PTRCH_GLOBAL_TYPE\":\"0\",\"PTRCH_CLIENT_NO\":\"10002920274\",\"RESCIND_DATE\":\"\",\"PTRCH_GLOBAL_ID\":\"610111199109260092\",\"PTRCH_CLIENT_NAME\":\"哈阿是噶是\",\"RESCIND_TELLER_NO\":\"\",\"CERT_NO\":\"11\",\"KID_CLIENT_NO\":\"10002920276\",\"SIGN_ID\":\"8\",\"MATURE_DATE\":\"20260926\",\"KID_CLIENT_NAME\":\"鱼哈\",\"HSLDR_FLAG\":\"Y\",\"REMARK\":\"\"},{\"OPERATION_TELLER_NO\":\"000227\",\"KID_CARD_NO\":\"6231500005627739\",\"START_DATE\":\"20191017\",\"SIGN_STATUS\":\"A\",\"LAST_UPDATE_DATE\":\"20191017\",\"PTRCH_GLOBAL_TYPE\":\"0\",\"PTRCH_CLIENT_NO\":\"10002920274\",\"RESCIND_DATE\":\"\",\"PTRCH_GLOBAL_ID\":\"610111199109260092\",\"PTRCH_CLIENT_NAME\":\"哈阿是噶是\",\"RESCIND_TELLER_NO\":\"\",\"CERT_NO\":\"16\",\"KID_CLIENT_NO\":\"10002920280\",\"SIGN_ID\":\"12\",\"MATURE_DATE\":\"20260926\",\"KID_CLIENT_NAME\":\"好的很\",\"HSLDR_FLAG\":\"Y\",\"REMARK\":\"\"},{\"OPERATION_TELLER_NO\":\"000227\",\"KID_CARD_NO\":\"6231500005627732\",\"START_DATE\":\"20191017\",\"SIGN_STATUS\":\"A\",\"LAST_UPDATE_DATE\":\"20191017\",\"PTRCH_GLOBAL_TYPE\":\"0\",\"PTRCH_CLIENT_NO\":\"10002920274\",\"RESCIND_DATE\":\"\",\"PTRCH_GLOBAL_ID\":\"610111199109260092\",\"PTRCH_CLIENT_NAME\":\"哈阿是噶是\",\"RESCIND_TELLER_NO\":\"\",\"CERT_NO\":\"16\",\"KID_CLIENT_NO\":\"10002920233280\",\"SIGN_ID\":\"14\",\"MATURE_DATE\":\"20260926\",\"KID_CLIENT_NAME\":\"好的很\",\"HSLDR_FLAG\":\"Y\",\"REMARK\":\"\"}]}";
//        System.out.println(ckDecryptData(plainText));
        SM4Utils sm4 = new SM4Utils();
        sm4.secretKey = "asdfghjklqwertyu";
        plainText.getBytes("UTF-8");
        System.out.println("ECB模式");

        String cipherText = sm4.encryptData_ECB(plainText);
        System.out.println(cipherText);
        System.out.println("1vs+leE+EhIg16087f8AjrIdlXK68E3Gjw+mZIOrHiJWtP2oHY6zWFwXaPVDXizJM42x6/Qi5kKVaqaCe6sjFYOw57FlIM4DZ8wdbsfX10NTPggtYJo4XCSqZPzLVlWxYEoHzfZMIIqW0+p1Jal8U5YSIUD3npWcd0Kr1Rp2Tu+P9yaw//zkcVfJN/7TAd9j86L6+MvwH8NUXhQp7k9tt06WlIT61ES+bQx3bRt+vp+FzbLCExU1FjXYk94s7CypuMZFbXSZuNwkvr8MDhW13u36HXHPVm+gCk6ahdiGEJiXlRD8MmJNAvTELq2ykWPV+EBzW9pIMP3Oe2MmoFOYA4k3QOUt7Gx9/T7NeCY/iDCCEpXk09QF0JZGFoZ6jk08yoF5erSU6oIoZJobGhzHnA7CFuKLEtRrZiduDkiUmdcbKHK77k8S1kl7hTVd05mrdx7Ia8wnRAeslWSApBhvcBk3TsT0NFXnEqlMV5KtQ59hsyRwl2zMQJzT82wmo2oULE1UGRpOlzx36PzPau7THd6FW2/6FBFRyscY3Fer/4K7XwkfcdtTJrt9lggqS1xnCfR947kwRgFN3aZO0HSKb7OwN93PYlNvZMlj1ZbomH9YNnEgifhqFGdGm2jhUctqAE3wGDti7S5/CtIsTdb8EOPrmJl2z+v1ZA/3pXoKmS0Oi/bpxCFCY9diE0QhWVnW067EmK7FDoO8nYNeadIIUhWr6SWvVrXRQl6+GC5IOLiX7G8D2BhOELk94oDVRIRDf07xVv5SMUJ/JEcBRmkLrh+saYXJmISYThpklc7EifQeV3g0Wt+bYd/j/I42feMWgpwg1ID3GCzNlH2qJoAq/tsxvE9y+tAB1V3uGT/WxNDH99ksMeSxOFHQYIb2BvGH3HkR6BxXC8fLG62u1Yle8I0fZnfAEPYNM5LRXZYpKkBskPZv7kVAhleQMBm23Xjr6cpujsZZH/wX0fJGZfawkwtNlQ8bqc1agP0C8iZL+7o6Wtq6TSANTbD8szLuw/QYb9ndVqDUPN0ZuEkQCmh2+HYBaHhfCmIurgBCLGM2LLvmwNViYX/BLT4RN3IPg3y+V/6kon/XIo+vbt6NAetMC/u4aLwSz6t9lTcHid7vQAdFmEBrKXDVCbXUqydsDbPkGSOJ8eYAULDg4KN0GnEvdv5N1QU6BAM15fxYGDmpL9GQEXFauYTbU0OpT9SV9iSIp+3hSN1SQnY+qoGXIzH7PYUOqynjMPMWIZolUmZ561dzAakjjln41tiqnJcZZyM2orGaQCOsGmt6yrPXIKmS3TPkIx1J4cDYs+UnZqN4a+wptI4k3Jh3zi4h4ItNACOi+i6GwygqEtTm3adIvLVS0eOdMFwOwpR1cAwxGMZ9c9HCX4MZaqx4qr9w3bs6Z38tU8KvTcrYdRoyhcK7fVEP+KMlfUixhuUfgl8ZSaFdTgdRH6uqPLkoFPhjqBMiec647mKASxoml+3czitRYrky7r/uKK4izVl4cD9uKAxD+N474ZHeGDSPeR0RRmdIO7/ez7VCf7tdEsfxnSzvFHQ4zYxN1HWGnhCpTOlKEXXopaMj+81Al0+gywtj+DXcjWlJBEqW7/aOlvdyQ/ylrTdgHbSpOxluxScHd92aIe7CfhPcjD3Nv240TDMu5B9LIdrxLfg/ArqxtWHxlSH62VTP2v/s6HVJZZrYYsCaQ8N8UR0etlNoBBBj5HZNtw7HNSvM/jDhxyObnTIqqjq+9Hr6jt6FW2/6FBFRyscY3Fer/4K7XwkfcdtTJrt9lggqS1xni/a8Kr2tv2HmhrSGRlALzm6u57XKzLWIA3swQxpJ98EkZJAo8BSFY5xl20iBSCDdyF+pPKaDdJEd2i8xtDBZdg==");

        plainText = sm4.decryptData_ECB(cipherText);
        System.out.println(plainText);
//        String aa = ckDecryptData("dxyDflLXbNuloZdqM3LYPjMtPxjlfyJMyNyyHDMf7mCGvbF807HyBqIfIeiSLSUV7S5SMqaQbK64s38Bam8F2wfK30HiL1jjaKmV5n7z8T2yAA9wfuGMXQn9LRvip6TIBBZcsKs0ZNTJoXDNsig4tPbf5I7Nll1ruMpiHfUeCbk2tJZIj3nfyav7EfnyRlTLMaKNYbgoAFfxfM5fRlC0xg==");
        System.out.println("明文: " + plainText);
//        System.out.println("aaa" + aa);

        JSONObject jsonObject = JSON.parseObject(plainText);
        jsonObject.getString("data");
        System.out.println("CBC模式");

        sm4.iv = jsonObject.getString("vi");
        cipherText = sm4.encryptData_CBC(jsonObject.getString("data"));
        System.out.println("密文: " + cipherText);
        System.out.println("");

        plainText = sm4.decryptData_CBC(jsonObject.getString("data"));
        System.out.println("明文: " + plainText);
        //PI4ke7HMoUMD/LOSHWX5/g==

        JSONObject jsonObjectPlainText = JSON.parseObject(plainText);
        jsonObjectPlainText.getString("data");
//        System.out.println(jsonObjectPlainText.getString("encrypt"));
//        System.out.println(jsonObjectPlainText.getString("encrypt"));
//        System.out.println(SM3.convert("rzy123456"));
        System.out.println(SM3.convert(jsonObject.getString("data")));
        System.out.println(jsonObject.getString("encrypt"));
        System.out.println(SM3.convert("{\"ckSignRelationRequestList\":[{\"OPERATION_TELLER_NO\":\"000227\",\"KID_CARD_NO\":\"6231500005627705\",\"START_DATE\":\"20191017\",\"SIGN_STATUS\":\"A\",\"LAST_UPDATE_DATE\":\"20191017\",\"PTRCH_GLOBAL_TYPE\":\"0\",\"PTRCH_CLIENT_NO\":\"10002920274\",\"RESCIND_DATE\":\"\",\"PTRCH_GLOBAL_ID\":\"610111199109260092\",\"PTRCH_CLIENT_NAME\":\"哈阿是噶是\",\"RESCIND_TELLER_NO\":\"\",\"CERT_NO\":\"11\",\"KID_CLIENT_NO\":\"10002920276\",\"SIGN_ID\":\"8\",\"MATURE_DATE\":\"20260926\",\"KID_CLIENT_NAME\":\"鱼哈\",\"HSLDR_FLAG\":\"Y\",\"REMARK\":\"\"},{\"OPERATION_TELLER_NO\":\"000227\",\"KID_CARD_NO\":\"6231500005627739\",\"START_DATE\":\"20191017\",\"SIGN_STATUS\":\"A\",\"LAST_UPDATE_DATE\":\"20191017\",\"PTRCH_GLOBAL_TYPE\":\"0\",\"PTRCH_CLIENT_NO\":\"10002920274\",\"RESCIND_DATE\":\"\",\"PTRCH_GLOBAL_ID\":\"610111199109260092\",\"PTRCH_CLIENT_NAME\":\"哈阿是噶是\",\"RESCIND_TELLER_NO\":\"\",\"CERT_NO\":\"16\",\"KID_CLIENT_NO\":\"10002920280\",\"SIGN_ID\":\"12\",\"MATURE_DATE\":\"20260926\",\"KID_CLIENT_NAME\":\"好的很\",\"HSLDR_FLAG\":\"Y\",\"REMARK\":\"\"},{\"OPERATION_TELLER_NO\":\"000227\",\"KID_CARD_NO\":\"6231500005627732\",\"START_DATE\":\"20191017\",\"SIGN_STATUS\":\"A\",\"LAST_UPDATE_DATE\":\"20191017\",\"PTRCH_GLOBAL_TYPE\":\"0\",\"PTRCH_CLIENT_NO\":\"10002920274\",\"RESCIND_DATE\":\"\",\"PTRCH_GLOBAL_ID\":\"610111199109260092\",\"PTRCH_CLIENT_NAME\":\"哈阿是噶是\",\"RESCIND_TELLER_NO\":\"\",\"CERT_NO\":\"16\",\"KID_CLIENT_NO\":\"10002920233280\",\"SIGN_ID\":\"14\",\"MATURE_DATE\":\"20260926\",\"KID_CLIENT_NAME\":\"好的很\",\"HSLDR_FLAG\":\"Y\",\"REMARK\":\"\"}]}"));
//        System.out.println(SM3.convert(jsonObjectPlainText.getString("data")));
        JSONObject jsonObject1 = JSONObject.parseObject("{\n" +
                "\t\t\t\"createtime\":\"Mon Oct 21 11:46:08 CST 2019\",\n" +
                "\t\t\t\"SUCCEED\":\"succeed\",\n" +
                "\t\t\t\"logname\":\"登录日志\",\n" +
                "\t\t\t\"logname\":\"登录日志\",\n" +
                "\t\t\t\"logname\":\"登录日志\",\n" +
                "\t\t\t\"logname\":\"登录日志\",\n" +
                "\t\t\t\"logname\":\"登录日志\",\n" +
                "\t\t\t\"ip\":\"0:0:0:0:0:0:0:1\",\n" +
                "\t\t\t\"IP\":\"ip\",\n" +
                "\t\t\t\"CREATETIME\":\"createtime\"\n" +
                "\t\t}");
        jsonObject1.forEach((newMap2,newMap1)->{
            System.out.println(newMap2 + "->" + newMap1);
//            System.out.println(newMap2);

        });
        Map<String, Object> stringObjectMap = jsonObject1.getInnerMap();
        HashMap<String, String[]> newMap = new HashMap<>();


        String secretKey = "11HDESaAhiHHugDz";
        String iv = "uisnfieoqa192a14";
        sm4.setSecretKey(secretKey);
        sm4.setIv(iv);
        String cbcJson = sm4.encryptData_CBC(jsonObject1.toJSONString());

        JSONObject c1Obj = new JSONObject();
        c1Obj.put("data", cbcJson);
        c1Obj.put("iv", iv);
        c1Obj.put("encrypt", SM3.convert(jsonObject1.toJSONString()));


        JSONObject c2Obj = new JSONObject();
        c2Obj.put("data", sm4.encryptData_ECB(c1Obj.toJSONString()));
        System.out.println(c2Obj.toJSONString());
    }


}
