public class TestRegex {
    public static void main(String[] args) {
        String token = "token=abc_s_def_\\_ghi&other=value";
        System.out.println("S1: " + token.replaceAll("(access_token|token)=[^&\\\\s]*", "$1=[REDACTED]"));
        
        String token2 = "token=abc\ndef&other=value";
        System.out.println("S2: " + token2.replaceAll("(access_token|token)=[^&\\\\s]*", "$1=[REDACTED]"));
    }
}
