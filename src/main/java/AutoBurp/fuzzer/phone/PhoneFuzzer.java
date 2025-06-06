package AutoBurp.fuzzer.phone;

import AutoBurp.generator.PhonePayloadGeneratorFactory;
import burp.*;

public class PhoneFuzzer implements IIntruderPayloadGeneratorFactory {
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;

    public PhoneFuzzer(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks) {
        this.helpers = helpers;
        this.callbacks = callbacks;
    }

    @Override
    public String getGeneratorName() {
        
        return "Phone Bypass Fuzzer";
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {
        
        return new PhonePayloadGeneratorFactory(this.helpers, attack, this.callbacks);
    }
}
