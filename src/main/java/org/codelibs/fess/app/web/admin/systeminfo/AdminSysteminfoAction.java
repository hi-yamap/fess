/*
 * Copyright 2012-2015 CodeLibs Project and the Others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */
package org.codelibs.fess.app.web.admin.systeminfo;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Resource;

import org.codelibs.core.lang.StringUtil;
import org.codelibs.core.misc.DynamicProperties;
import org.codelibs.fess.Constants;
import org.codelibs.fess.app.web.base.FessAdminAction;
import org.codelibs.fess.helper.SystemHelper;
import org.lastaflute.web.Execute;
import org.lastaflute.web.callback.ActionRuntime;
import org.lastaflute.web.response.HtmlResponse;
import org.lastaflute.web.response.render.RenderData;

/**
 * @author Keiichi Watanabe
 */
public class AdminSysteminfoAction extends FessAdminAction {

    // ===================================================================================
    //                                                                           Attribute
    //                                                                           =========
    @Resource
    private SystemHelper systemHelper;
    @Resource
    protected DynamicProperties crawlerProperties;

    private static final String[] bugReportLabels = { "file.separator", "file.encoding", "java.runtime.version", "java.vm.info",
            "java.vm.name", "java.vm.vendor", "java.vm.version", "os.arch", "os.name", "os.version", "user.country", "user.language",
            "user.timezone" };

    // ===================================================================================
    //                                                                               Hook
    //                                                                              ======
    @Override
    protected void setupHtmlData(final ActionRuntime runtime) {
        super.setupHtmlData(runtime);
        runtime.registerData("helpLink", systemHelper.getHelpLink("systemInfo"));
    }

    // ===================================================================================
    //                                                                              Index
    //                                                                      ==============
    @Execute
    public HtmlResponse index(final SystemInfoForm form) {
        return asHtml(path_AdminSysteminfo_AdminSysteminfoJsp).renderWith(data -> {
            registerEnvItems(data);
            registerPropItems(data);
            registerFessPropItems(data);
            registerBugReportItems(data);
        });
    }

    // ===================================================================================
    //                                                                        Assist Logic
    //                                                                        ============

    protected void registerEnvItems(final RenderData data) {
        final List<Map<String, String>> itemList = new ArrayList<Map<String, String>>();
        for (final Map.Entry<String, String> entry : System.getenv().entrySet()) {
            itemList.add(createItem(entry.getKey(), entry.getValue()));
        }
        data.register("envItems", itemList);
    }

    protected void registerPropItems(final RenderData data) {
        final List<Map<String, String>> itemList = new ArrayList<Map<String, String>>();
        for (final Map.Entry<Object, Object> entry : System.getProperties().entrySet()) {
            itemList.add(createItem(entry.getKey(), entry.getValue()));
        }
        data.register("propItems", itemList);
    }

    protected void registerFessPropItems(final RenderData data) {
        final List<Map<String, String>> itemList = new ArrayList<Map<String, String>>();
        for (final Map.Entry<Object, Object> entry : crawlerProperties.entrySet()) {
            itemList.add(createItem(entry.getKey(), entry.getValue()));
        }
        data.register("fessPropItems", itemList);
    }

    protected void registerBugReportItems(final RenderData data) {
        final List<Map<String, String>> itemList = new ArrayList<Map<String, String>>();
        for (final String label : bugReportLabels) {
            itemList.add(createPropItem(label));
        }

        for (final Map.Entry<Object, Object> entry : crawlerProperties.entrySet()) {
            if (isBugReportTarget(entry.getKey())) {
                itemList.add(createItem(entry.getKey(), entry.getValue()));
            }
        }

        data.register("bugReportItems", itemList);
    }

    private boolean isBugReportTarget(final Object key) {
        if ("snapshot.path".equals(key) || "label.value".equals(key)) {
            return false;
        }
        return true;
    }

    protected Map<String, String> createPropItem(final String key) {
        return createItem(key, System.getProperty(key));
    }

    protected Map<String, String> createItem(final Object label, final Object value) {
        final Map<String, String> map = new HashMap<String, String>(2);
        map.put(Constants.ITEM_LABEL, label != null ? label.toString() : StringUtil.EMPTY);
        map.put(Constants.ITEM_VALUE, value != null ? value.toString() : StringUtil.EMPTY);
        return map;
    }

}
